//! AUD-002 protocol harness: reads one JSON request per line on stdin, runs it through the public
//! API of mhfe-core and writes one JSON answer per line on stdout. The Python scripts beside it
//! compute every expected answer on their own and compare.
//!
//!   aud002-protocol-adapter            serves JSON lines until stdin ends
//!   aud002-protocol-adapter nfkd-cost  times `Seed::derive` as a passphrase doubles (SEC-007)
//!
//! A request it cannot read ends the program with exit 2, so that the script that sent it fails.
//!
//! Argon2id is replaced by a stand-in engine, a SHA-256 of its whole input, which the Python side
//! reproduces: the protocol around Argon2id (packing, salts, masks, halves, rounds, length rules)
//! is then compared at full width without any memory-hard work. The stand-in also records each
//! call, so a refusal can be shown to come before any Argon2id work.

mod nfkd_cost;

use std::io::{self, BufRead, Write};
use std::ops::ControlFlow;
use std::process::ExitCode;

use mhfe_core::password_check::{self, Check, EFF_WORDS};
use mhfe_core::repair::{Card, Repaired};
use mhfe_core::wallet_check::{self, Seed};
use mhfe_core::{Argon2Engine, Error, Mhfe, Password, Phrase, Suite, WorkFactor};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// The tag of the stand-in engine, which the Python side uses too.
const STAND_IN_TAG: &[u8] = b"AUD-002 stand-in Argon2id";

/// key = SHA-256(TAG || BE32(memory_kib) || BE32(passes) || BE32(len P) || P || salt).
struct StandIn {
    calls: Vec<Value>,
}

impl Argon2Engine for StandIn {
    fn argon2id(
        &mut self,
        password: &[u8],
        salt: &[u8; 16],
        memory_kib: u32,
        passes: u32,
        key: &mut [u8; 32],
    ) -> Result<(), Error> {
        // A password holds at most `Password::MAX_BYTES` (1,024) bytes, so its length fits 32 bits.
        let digest = Sha256::new()
            .chain_update(STAND_IN_TAG)
            .chain_update(memory_kib.to_be_bytes())
            .chain_update(passes.to_be_bytes())
            .chain_update((password.len() as u32).to_be_bytes())
            .chain_update(password)
            .chain_update(salt)
            .finalize();
        key.copy_from_slice(&digest);
        self.calls
            .push(json!([to_hex(salt), memory_kib, passes, to_hex(password)]));
        Ok(())
    }
}

/// The answer to one request, or why the request could not be read.
type Answer = Result<Value, String>;

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn from_hex(text: &str) -> Result<Vec<u8>, String> {
    (0..text.len())
        .step_by(2)
        .map(|at| {
            text.get(at..at + 2)
                .and_then(|pair| u8::from_str_radix(pair, 16).ok())
                .ok_or_else(|| format!("not hex: {text}"))
        })
        .collect()
}

fn err<E: std::fmt::Debug>(error: E) -> Value {
    json!({ "err": format!("{error:?}") })
}

/// A suite number, or none when the request leaves it out (null).
fn suite_of(value: &Value) -> Result<Option<Suite>, String> {
    match value.as_u64() {
        Some(3) => Ok(Some(Suite::TwentyFourWords)),
        Some(4) => Ok(Some(Suite::SameLength)),
        None if value.is_null() => Ok(None),
        _ => Err(format!("not a suite: {value}")),
    }
}

fn suite_number(suite: Suite) -> u64 {
    if suite == Suite::TwentyFourWords {
        3
    } else {
        4
    }
}

/// A stated number of words, or none when the request leaves it out (null).
fn stated_of(value: &Value) -> Result<Option<usize>, String> {
    match value.as_u64() {
        Some(words) => usize::try_from(words)
            .map(Some)
            .map_err(|_| format!("too many words: {words}")),
        None if value.is_null() => Ok(None),
        None => Err(format!("not a number of words: {value}")),
    }
}

fn text<'a>(request: &'a Value, field: &str) -> Result<&'a str, String> {
    request[field]
        .as_str()
        .ok_or_else(|| format!("no text {field}"))
}

fn number<T: TryFrom<u64>>(request: &Value, field: &str) -> Result<T, String> {
    request[field]
        .as_u64()
        .and_then(|value| T::try_from(value).ok())
        .ok_or_else(|| format!("no number {field} in range"))
}

fn list<'a>(request: &'a Value, field: &str) -> Result<&'a [Value], String> {
    request[field]
        .as_array()
        .map(Vec::as_slice)
        .ok_or_else(|| format!("no list {field}"))
}

/// A phrase the request gives as valid input of another call.
fn phrase(request: &Value, field: &str) -> Result<Phrase, String> {
    Phrase::read(text(request, field)?).map_err(|error| format!("{field} is not a phrase: {error}"))
}

/// The crate's answer to the request's cost (a refusal is an answer to compare), or why the request
/// could not be read.
fn work_of(request: &Value) -> Result<Result<WorkFactor, Error>, String> {
    Ok(WorkFactor::new(
        number(request, "pim")?,
        number(request, "mem")?,
    ))
}

fn encrypt(request: &Value) -> Answer {
    let original = match Phrase::read(text(request, "phrase")?) {
        Ok(phrase) => phrase,
        Err(error) => return Ok(err(error)),
    };
    let password = match Password::new(text(request, "password")?) {
        Ok(password) => password,
        Err(error) => return Ok(err(error)),
    };
    let work = match work_of(request)? {
        Ok(work) => work,
        Err(error) => return Ok(err(error)),
    };
    let suite = suite_of(&request["suite"])?.ok_or("encrypt needs a suite")?;
    let mut cipher = Mhfe::with_engine(work, StandIn { calls: Vec::new() });
    let mut rounds = Vec::new();
    let mut shown = Vec::new();
    let result = cipher.encrypt(
        &original,
        &password,
        suite,
        &mut |round, of| {
            rounds.push(json!([round, of]));
            ControlFlow::Continue(())
        },
        &mut |unchecked| {
            shown.push(unchecked.as_str().to_owned());
            ControlFlow::Continue(())
        },
    );
    let calls = cipher.engine().calls.clone();
    Ok(match result {
        Ok(container) => json!({
            "ok": container.as_str(),
            "words": container.words(),
            "shown": shown,
            "rounds": rounds,
            "calls": calls,
        }),
        Err(error) => json!({ "err": format!("{error:?}"), "calls": calls.len() }),
    })
}

fn decrypt(request: &Value) -> Answer {
    let container = match Phrase::read(text(request, "container")?) {
        Ok(phrase) => phrase,
        Err(error) => return Ok(err(error)),
    };
    let password = match Password::new(text(request, "password")?) {
        Ok(password) => password,
        Err(error) => return Ok(err(error)),
    };
    let work = match work_of(request)? {
        Ok(work) => work,
        Err(error) => return Ok(err(error)),
    };
    let mut cipher = Mhfe::with_engine(work, StandIn { calls: Vec::new() });
    let result = cipher.decrypt(
        &container,
        &password,
        stated_of(&request["stated"])?,
        suite_of(&request["suite"])?,
        &mut |_, _| ControlFlow::Continue(()),
    );
    let calls = cipher.engine().calls.len();
    let recovery = match result {
        Ok(recovery) => recovery,
        Err(error) => return Ok(json!({ "err": format!("{error:?}"), "calls": calls })),
    };
    let mut readings = Vec::new();
    for stated in list(request, "readings")? {
        readings.push(match recovery.readings(stated_of(stated)?) {
            Ok(readings) => json!({
                "ok": readings
                    .iter()
                    .map(|reading| json!({
                        "words": reading.phrase().words(),
                        "verified": reading.is_verified(),
                        "phrase": reading.phrase().as_str(),
                    }))
                    .collect::<Vec<_>>()
            }),
            Err(error) => err(error),
        });
    }
    Ok(json!({
        "ok": {
            "suite": suite_number(recovery.suite()),
            "detected": recovery.detected_lengths(),
            "readings": readings,
        },
        "calls": calls,
    }))
}

fn draw(request: &Value) -> Answer {
    let trials: Vec<Vec<u8>> = list(request, "trials")?
        .iter()
        .map(|trial| from_hex(trial.as_str().ok_or("a trial that is not text")?))
        .collect::<Result<_, String>>()?;
    let mut used = 0;
    let result = wallet_check::draw(text(request, "passphrase")?, &mut |entropy| match trials
        .get(used)
    {
        Some(trial) => {
            entropy.copy_from_slice(trial);
            used += 1;
            ControlFlow::Continue(())
        }
        None => ControlFlow::Break(()),
    });
    Ok(match result {
        Ok(phrase) => json!({ "ok": phrase.as_str(), "used": used }),
        Err(error) => json!({ "err": format!("{error:?}"), "used": used }),
    })
}

fn repair(request: &Value) -> Answer {
    Ok(
        match Repaired::of(text(request, "written")?, text(request, "card")?) {
            Ok(repaired) => json!({
                "ok": repaired.container().as_str(),
                "changes": repaired
                    .changes()
                    .map(|change| {
                        json!([change.on_card(), change.position(), change.read(), change.word()])
                    })
                    .collect::<Vec<_>>(),
            }),
            Err(error) => err(error),
        },
    )
}

fn check(request: &Value) -> Answer {
    Ok(match Check::of(text(request, "password")?) {
        Check::Fits => json!({ "kind": "Fits" }),
        Check::OneErased { position, word } => {
            json!({ "kind": "OneErased", "position": position, "word": word })
        }
        Check::Mismatch { candidates } => json!({ "kind": "Mismatch", "candidates": candidates }),
        Check::NotApplicable => json!({ "kind": "NotApplicable" }),
    })
}

fn handle(request: &Value) -> Answer {
    Ok(match text(request, "op")? {
        "password" => match Password::new(text(request, "text")?) {
            Ok(password) => json!({ "ok": to_hex(password.as_bytes()) }),
            Err(error) => err(error),
        },
        "read" => match Phrase::read(text(request, "text")?) {
            Ok(phrase) => json!({ "ok": phrase.as_str(), "words": phrase.words() }),
            Err(error) => err(error),
        },
        "read_word" => json!({ "ok": Phrase::read_word(text(request, "token")?) }),
        "from_entropy" => match Phrase::from_entropy(&from_hex(text(request, "entropy")?)?) {
            Ok(phrase) => json!({ "ok": phrase.as_str(), "words": phrase.words() }),
            Err(error) => err(error),
        },
        "other_lengths" => json!({ "ok": phrase(request, "phrase")?.other_detected_lengths() }),
        "encrypt" => encrypt(request)?,
        "decrypt" => decrypt(request)?,
        "seed" => {
            let seed = Seed::derive(&phrase(request, "phrase")?, text(request, "passphrase")?);
            json!({ "seed": to_hex(seed.as_bytes()), "passes": seed.passes() })
        }
        "draw" => draw(request)?,
        "card" => match Card::new(&phrase(request, "container")?, number(request, "k")?) {
            Ok(card) => json!({ "ok": card.as_str() }),
            Err(error) => err(error),
        },
        "repair" => repair(request)?,
        "check_word" => {
            let drawn = list(request, "drawn")?
                .iter()
                .map(|index| index.as_u64().and_then(|index| u16::try_from(index).ok()))
                .collect::<Option<Vec<u16>>>()
                .ok_or("a drawn index that is not a 16-bit number")?;
            let drawn = drawn
                .try_into()
                .map_err(|_| "not the number of drawn words check_word takes")?;
            json!({ "ok": password_check::check_word(drawn) })
        }
        "check" => check(request)?,
        "eff" => json!({ "ok": EFF_WORDS.to_vec() }),
        other => return Err(format!("unknown op {other}")),
    })
}

/// Answers each request on stdin with one line on stdout, until stdin ends.
fn serve() -> Result<(), String> {
    let stdin = io::stdin();
    let mut stdout = io::BufWriter::new(io::stdout().lock());
    for line in stdin.lock().lines() {
        let line = line.map_err(|error| format!("stdin: {error}"))?;
        if line.is_empty() {
            continue;
        }
        let request: Value =
            serde_json::from_str(&line).map_err(|error| format!("not a JSON request: {error}"))?;
        let answer = handle(&request)?;
        writeln!(stdout, "{answer}").map_err(|error| format!("stdout: {error}"))?;
    }
    stdout.flush().map_err(|error| format!("stdout: {error}"))
}

/// The exit code of a check that failed; 0 is a check that held.
const FAILED: u8 = 1;
/// The exit code of a request or a mode that could not be read, or a run that broke.
const BROKEN: u8 = 2;

fn main() -> ExitCode {
    let mode = std::env::args().nth(1);
    let outcome = match mode.as_deref() {
        None => serve().map(|()| true),
        Some("nfkd-cost") => nfkd_cost::run(),
        Some(other) => Err(format!(
            "unknown mode {other}; usage: aud002-protocol-adapter [nfkd-cost]"
        )),
    };
    match outcome {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(FAILED),
        Err(message) => {
            eprintln!("{message}");
            ExitCode::from(BROKEN)
        }
    }
}
