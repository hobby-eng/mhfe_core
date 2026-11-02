//! Bounded reproductions of the reviewed findings using public synthetic data only.

use std::fs;
use std::ops::ControlFlow;

use mhfe_core::{Argon2Engine, Mhfe, Password, Phrase, Suite, WorkFactor};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::{EVIDENCE, Result};

struct HashEngine;

impl Argon2Engine for HashEngine {
    fn argon2id(
        &mut self,
        password: &[u8],
        salt: &[u8; 16],
        memory_kib: u32,
        passes: u32,
        key: &mut [u8; 32],
    ) -> std::result::Result<(), mhfe_core::Error> {
        let digest = Sha256::new()
            .chain_update(b"AUD-005 public synthetic engine")
            .chain_update(password)
            .chain_update(salt)
            .chain_update(memory_kib.to_be_bytes())
            .chain_update(passes.to_be_bytes())
            .finalize();
        key.copy_from_slice(&digest);
        Ok(())
    }
}

fn cancellation_documentation(repair: &str, security: &str) -> Result<()> {
    if !repair.contains("gives it out once `encrypt`\n//! returns `Ok`.") {
        return Err("repair publication guidance changed".into());
    }
    if !security.contains("before `encrypt` returns `Ok`.") {
        return Err("security publication guidance changed".into());
    }
    Ok(())
}

fn cancelled_creation() -> Result<Value> {
    cancellation_documentation(
        &fs::read_to_string("src/repair.rs")?,
        &fs::read_to_string("SECURITY.md")?,
    )?;
    let original = Phrase::read(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    )?;
    let password = Password::new("public test password")?;
    let mut cipher = Mhfe::with_engine(WorkFactor::default(), HashEngine);
    let mut rounds = Vec::new();
    let mut unchecked_words = None;
    let mut on_round = |round, _| {
        rounds.push(round);
        if round == 13 {
            ControlFlow::Break(())
        } else {
            ControlFlow::Continue(())
        }
    };
    let mut on_unchecked = |container: &Phrase| {
        unchecked_words = Some(container.words());
        ControlFlow::Continue(())
    };
    let result = cipher.encrypt(
        &original,
        &password,
        Suite::TwentyFourWords,
        &mut on_round,
        &mut on_unchecked,
    )?;
    if !matches!(result, ControlFlow::Break(())) || unchecked_words != Some(24) {
        return Err("creation did not stop at the first reverse-check round".into());
    }
    if rounds != (1..=13).collect::<Vec<_>>() {
        return Err("unexpected callback sequence before cancellation".into());
    }
    Ok(json!({
        "result": "Ok(ControlFlow::Break(()))",
        "uncheckedContainerWords": unchecked_words,
        "callbacks": rounds,
        "reverseComparisonCompleted": false,
        "documentedReleaseCondition": "Ok"
    }))
}

fn nfkd_overflow() -> Result<Value> {
    let repetitions = 130_150_525_u64;
    let decomposed_bytes = 33_u64;
    let total = repetitions * decomposed_bytes;
    let wrapped = total % (1_u64 << 32);
    if total != 4_294_967_325 || wrapped != 29 || repetitions * 3 != 390_451_575 {
        return Err("32-bit NFKD boundary arithmetic changed".into());
    }
    if (repetitions - 1) * decomposed_bytes > u32::MAX.into() {
        return Err("preceding NFKD boundary case does not fit u32".into());
    }
    let source = fs::read_to_string("src/nfkd.rs")?;
    for pattern in [
        "bytes += part.len_utf8()",
        "Secret::zeroed(self.bytes)",
        "part.encode_utf8(&mut out[end..end + width])",
    ] {
        if !source.contains(pattern) {
            return Err(format!("NFKD source fact is absent: {pattern}").into());
        }
    }
    Ok(json!({
        "targetPointerBits": 32,
        "inputBytes": repetitions * 3,
        "decomposedBytes": total,
        "wrappedBytes": wrapped,
        "precedingCountFits": true,
        "expected": "PasswordTooLong before writing",
        "sourceResult": "wrapped success branch followed by a bounds panic; overflow checks can panic earlier",
        "runtimeExecuted": false
    }))
}

fn windows_report_blocks() -> Result<Value> {
    const REGISTRATION_LIMIT: u64 = 512;
    let block = u64::from(u32::MAX);
    let mut levels = Vec::new();
    for level in [20, 21] {
        let kib = u64::from(WorkFactor::new(0, level)?.memory_kib());
        let bytes = kib * 1024;
        let required = bytes.div_ceil(block);
        let registered = required.min(REGISTRATION_LIMIT);
        let uncovered = bytes - registered * block;
        levels.push(json!({
            "memoryLevel": level,
            "bytes": bytes,
            "requiredRegistrations": required,
            "availableWithoutOtherSecrets": REGISTRATION_LIMIT,
            "uncoveredBytes": uncovered
        }));
    }
    if levels[0]["requiredRegistrations"] != 513
        || levels[0]["uncoveredBytes"] != 512
        || levels[1]["requiredRegistrations"] != 769
        || levels[1]["uncoveredBytes"] != 1_099_511_628_288_u64
    {
        return Err("Windows WER registration arithmetic changed".into());
    }
    let source = fs::read_to_string("src/os/windows.rs")?;
    for pattern in [
        "const REPORT_BLOCK: usize = u32::MAX as usize;",
        "if !registered {",
        "break;",
        "self.excluded == self.bytes.div_ceil(REPORT_BLOCK)",
    ] {
        if !source.contains(pattern) {
            return Err(format!("Windows source fact is absent: {pattern}").into());
        }
    }
    Ok(json!({
        "registrationLimit": REGISTRATION_LIMIT,
        "levels": levels,
        "smallWorkAreaAfter512LiveSecrets": {
            "bytes": 65_536,
            "availableRegistrations": 0,
            "uncoveredBytes": 65_536
        },
        "windowsRuntimeExecuted": false
    }))
}

fn source_contracts() -> Result<Value> {
    let probe = fs::read_to_string("docs/audits/AUD-003-harnesses/sec/probe-stack/src/main.rs")?;
    let wrapper = fs::read_to_string("docs/audits/AUD-003-harnesses/sec/run-matrix.sh")?;
    let ignored_reads = probe.matches("let _ = mem.read_exact_at").count();
    if ignored_reads != 2 || !probe.contains("let mut bytes = vec![0u8; end - start];") {
        return Err("stack probe no longer has the reviewed unread-page path".into());
    }
    if wrapper.contains("38") || !wrapper.contains("[ \"$found\" -eq 0 ]") {
        return Err("stack wrapper contract changed".into());
    }
    let readme = fs::read_to_string("README.md")?;
    let library = fs::read_to_string("src/lib.rs")?;
    let error = fs::read_to_string("src/error.rs")?;
    if !readme.contains("You need Rust 1.99 or later and a 64-bit target.")
        || !library.contains("a 32-bit WebAssembly host")
        || !error.contains("cancellation")
    {
        return Err("documentation source facts changed".into());
    }
    Ok(json!({
        "stackProbe": {
            "ignoredReadResultSites": ignored_reads,
            "positiveControlRequiredByWrapper": false,
            "completionMarkerCanFollowUnreadPages": true
        },
        "readmeRequires64BitWithoutWasmException": true,
        "errorModuleStillNamesCancellation": true
    }))
}

pub(crate) fn negative_controls() -> Result<()> {
    let repair = fs::read_to_string("src/repair.rs")?;
    let security = fs::read_to_string("SECURITY.md")?;
    cancellation_documentation(&repair, &security)?;
    let corrected_repair =
        repair.replace("returns `Ok`.", "returns `Ok(ControlFlow::Continue(_))`.");
    if corrected_repair == repair
        || cancellation_documentation(&corrected_repair, &security).is_ok()
    {
        return Err("corrected repair publication guidance was accepted".into());
    }
    let corrected_security = security.replace(
        "before `encrypt` returns `Ok`.",
        "before `encrypt` returns `Ok(ControlFlow::Continue(_))`.",
    );
    if corrected_security == security
        || cancellation_documentation(&repair, &corrected_security).is_ok()
    {
        return Err("corrected security publication guidance was accepted".into());
    }
    println!("two corrected publication-guidance controls refused");
    Ok(())
}

pub(crate) fn source_findings() -> Result<()> {
    let value = json!({
        "cancelledCreation": cancelled_creation()?,
        "nfkdOverflow32Bit": nfkd_overflow()?,
        "windowsWerCoverage": windows_report_blocks()?,
        "sourceContracts": source_contracts()?
    });
    fs::create_dir_all(EVIDENCE)?;
    fs::write(
        format!("{EVIDENCE}/finding-probes.json"),
        serde_json::to_vec_pretty(&value)?,
    )?;
    println!("source-findings: five reviewed defect groups reproduced or source-confirmed");
    Ok(())
}
