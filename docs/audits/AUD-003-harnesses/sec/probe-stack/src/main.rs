//! Audit probe of AUD-003 (sec): what the real `NativeArgon2` leaves in process memory after
//! `argon2id` returns, read from outside the pool through /proc/self/mem, and how deep Argon2 writes
//! on the pool threads. Public test data only. Linux on x86-64; README.md says how to run it.
#![allow(
    unsafe_code,
    reason = "one exported symbol for a debugger to stop at; everything else is safe Rust"
)]
#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a probe with a main of its own: a failed read ends it"
)]
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::os::unix::fs::FileExt;

use argon2::{Algorithm, Argon2, Block, Params, Version};
use blake2::{Blake2b512, Digest};
use mhfe_core::{Argon2Engine, NativeArgon2};
use rayon::ThreadPoolBuilder;

const SALT: &[u8; 16] = b"0123456789abcdef";
const LANES: u32 = 4;
const MIB: usize = 1 << 20;

#[derive(Clone, Debug)]
struct Region {
    start: usize,
    end: usize,
    perms: String,
    name: String,
}

fn maps() -> Vec<Region> {
    let text = fs::read_to_string("/proc/self/maps").unwrap();
    text.lines()
        .map(|line| {
            let mut fields = line.split_whitespace();
            let (start, end) = fields.next().unwrap().split_once('-').unwrap();
            let perms = fields.next().unwrap().to_owned();
            let name = fields.skip(3).collect::<Vec<_>>().join(" ");
            Region {
                start: usize::from_str_radix(start, 16).unwrap(),
                end: usize::from_str_radix(end, 16).unwrap(),
                perms,
                name,
            }
        })
        .collect()
}

fn tids() -> Vec<u32> {
    fs::read_dir("/proc/self/task")
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_str().unwrap().parse().unwrap())
        .collect()
}

/// The stack pointer of a thread blocked in a system call, or `None` while it runs.
fn sp_of(tid: u32) -> Option<usize> {
    let text = fs::read_to_string(format!("/proc/self/task/{tid}/syscall")).ok()?;
    let fields: Vec<&str> = text.split_whitespace().collect();
    if fields.len() < 9 {
        return None;
    }
    usize::from_str_radix(fields[7].trim_start_matches("0x"), 16).ok()
}

/// Waits until every thread of `pool` sleeps, and returns its stack pointer.
fn idle_sps(pool: &[u32]) -> Vec<usize> {
    for _ in 0..2000 {
        let sps: Vec<Option<usize>> = pool.iter().map(|&tid| sp_of(tid)).collect();
        if sps.iter().all(Option::is_some) {
            std::thread::sleep(std::time::Duration::from_millis(5));
            return pool.iter().map(|&tid| sp_of(tid).unwrap()).collect();
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    panic!("the pool does not sleep");
}

fn memory() -> File {
    OpenOptions::new().read(true).write(true).open("/proc/self/mem").unwrap()
}

fn read(mem: &File, start: usize, end: usize) -> Vec<u8> {
    // Page by page: glibc's guard of a thread stack may lie inside the mapping (MADV_GUARD_INSTALL),
    // and a read of it fails.
    let mut bytes = vec![0u8; end - start];
    for (index, page) in bytes.chunks_mut(4096).enumerate() {
        let _ = mem.read_exact_at(page, (start + index * 4096) as u64);
    }
    bytes
}

/// What secrets of one call look like, as 8-byte patterns.
fn patterns(password: &[u8], memory_kib: u32, passes: u32) -> HashMap<u64, &'static str> {
    let mut table = HashMap::new();
    for window in password.windows(8) {
        table.insert(u64::from_ne_bytes(window.try_into().unwrap()), "password");
    }
    let params = Params::new(memory_kib, passes, LANES, Some(32)).unwrap();
    let mut digest = Blake2b512::new();
    digest.update(LANES.to_le_bytes());
    digest.update(32u32.to_le_bytes());
    digest.update(memory_kib.to_le_bytes());
    digest.update(passes.to_le_bytes());
    digest.update(0x13u32.to_le_bytes());
    digest.update(2u32.to_le_bytes());
    digest.update((password.len() as u32).to_le_bytes());
    digest.update(password);
    digest.update(16u32.to_le_bytes());
    digest.update(SALT);
    digest.update(0u32.to_le_bytes());
    digest.update(0u32.to_le_bytes());
    let h0 = digest.finalize();
    let mut blocks = vec![Block::new(); params.block_count()];
    let mut tag = [0u8; 32];
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params.clone());
    argon2
        .hash_password_into_with_memory(password, SALT, &mut tag, &mut blocks[..])
        .unwrap();
    for block in &blocks {
        for &word in block.as_ref() {
            table.insert(word, "block");
        }
    }
    let lane = blocks.len() / LANES as usize;
    let mut last = blocks[lane - 1];
    for index in 1..LANES as usize {
        last ^= &blocks[index * lane + lane - 1];
    }
    for &word in last.as_ref() {
        table.insert(word, "last-xor");
    }
    // Every window of H0, so that a copy at any offset of its own shows.
    for (index, window) in h0.windows(8).enumerate() {
        let name: &'static str = Box::leak(format!("H0+{index}").into_boxed_str());
        table.insert(u64::from_ne_bytes(window.try_into().unwrap()), name);
    }
    for window in tag.windows(8) {
        table.insert(u64::from_ne_bytes(window.try_into().unwrap()), "tag");
    }
    table
}

fn scan(name: &str, base: usize, bytes: &[u8], table: &HashMap<u64, &'static str>, hits: &mut usize) {
    scan_near(name, base, bytes, table, hits, 0);
}

fn scan_near(name: &str, base: usize, bytes: &[u8], table: &HashMap<u64, &'static str>, hits: &mut usize, sp: usize) {
    let mut counts: HashMap<&'static str, (usize, usize)> = HashMap::new();
    for (offset, window) in bytes.windows(8).enumerate() {
        let word = u64::from_ne_bytes(window.try_into().unwrap());
        if word == 0 {
            continue;
        }
        if let Some(kind) = table.get(&word) {
            let entry = counts.entry(kind).or_insert((0, base + offset));
            entry.0 += 1;
            entry.1 = entry.1.max(base + offset);
            *hits += 1;
        }
    }
    for (kind, (count, highest)) in counts {
        if sp != 0 {
            println!(
                "  {name}: {count} {kind} words, highest at {highest:#x}, sp {sp:#x}, {} below sp",
                sp as i64 - highest as i64
            );
        } else {
            println!("  {name}: {count} {kind} words, highest at {highest:#x}");
        }
    }
}

fn region_of(regions: &[Region], address: usize) -> Option<&Region> {
    regions.iter().find(|region| region.start <= address && address < region.end)
}

fn kind_of(word: u64, regions: &[Region]) -> String {
    if word == 0 {
        return "0".to_owned();
    }
    if word < 0x1_0000 {
        return format!("small {word}");
    }
    match region_of(regions, word as usize) {
        Some(region) => format!("ptr {} {}", region.perms, region.name),
        None => format!("OTHER {word:#018x}"),
    }
}

fn password_of(seed: u8, length: usize) -> Vec<u8> {
    let mut state = 0x9e37_79b9_7f4a_7c15u64 ^ u64::from(seed);
    (0..length)
        .map(|_| {
            state = state.wrapping_mul(0xbf58_476d_1ce4_e5b9).rotate_left(29) ^ 0x94d0_49bb;
            b'a' + (state >> 56) as u8 % 26
        })
        .collect()
}

/// The real engine, seen from outside: every stack and every writable mapping after a call.
fn real_scan(calls: usize, memory_kib: u32, passes: u32, length: usize) {
    let before = tids();
    let mut engine = NativeArgon2::new(memory_kib).unwrap();
    let pool: Vec<u32> = tids().into_iter().filter(|tid| !before.contains(tid)).collect();
    println!("pool threads: {pool:?}");
    let password = password_of(1, length);
    let other = password_of(2, length);
    let mut key = Box::new([0u8; 32]);
    let mem = memory();
    // Every writable mapping after one call, before the tables of this probe exist.
    engine.argon2id(&password, SALT, memory_kib, passes, &mut key).unwrap();
    idle_sps(&pool);
    let regions = maps();
    let total: usize = regions
        .iter()
        .filter(|region| region.perms.starts_with("rw") && !region.name.starts_with("[v"))
        .map(|region| region.end - region.start)
        .sum();
    let mut image = Vec::with_capacity(total + MIB);
    let mut places = Vec::new();
    for region in regions.iter().filter(|region| region.perms.starts_with("rw") && !region.name.starts_with("[v")) {
        let first = image.len();
        image.resize(first + (region.end - region.start), 0u8);
        for (index, page) in image[first..].chunks_mut(4096).enumerate() {
            let _ = mem.read_exact_at(page, (region.start + index * 4096) as u64);
        }
        places.push((region.clone(), first));
    }
    let table = patterns(&password, memory_kib, passes);
    println!("{} patterns; every writable mapping after the first call:", table.len());
    let mut hits = 0;
    for (region, first) in &places {
        let bytes = &image[*first..*first + (region.end - region.start)];
        scan(&format!("{:#x} {:?} {}", region.start, region.perms, region.name), region.start, bytes, &table, &mut hits);
    }
    println!("{hits} hits in the writable mappings after the first call");
    drop(image);
    // Every call from now on, with one password and then the other: every word of each stack that
    // is neither zero, nor a small number, nor an address of a mapping, by its offset from the
    // stack pointer of the sleeping thread.
    let mut seen: HashMap<i64, (usize, u64)> = HashMap::new();
    let mut values: HashMap<i64, std::collections::HashSet<u64>> = HashMap::new();
    let top_offset = {
        let sps = idle_sps(&pool);
        let regions = maps();
        let highest = *sps.iter().max().unwrap();
        region_of(&regions, highest).unwrap().end - highest
    };
    println!("top of each stack: {top_offset} bytes above its idle stack pointer");
    let regions = maps();
    let mut deep_zero_top = i64::MIN;
    for call in 0..calls {
        let (this, this_table) = (if call % 2 == 0 { &password } else { &other }, ());
        let _ = this_table;
        engine.argon2id(this, SALT, memory_kib, passes, &mut key).unwrap();
        let sps = idle_sps(&pool);
        for (&tid, &sp) in pool.iter().zip(&sps) {
            let low = sp - 300 * 1024;
            let high = sp + top_offset;
            let bytes = read(&mem, low, high);
            if call % 2 == 0 {
                scan_near(&format!("call {call} thread {tid} stack"), low, &bytes, &table, &mut hits, sp);
            }
            for (index, chunk) in bytes.chunks_exact(8).enumerate() {
                let word = u64::from_ne_bytes(chunk.try_into().unwrap());
                let address = low + index * 8;
                if kind_of(word, &regions).starts_with("OTHER") {
                    let entry = seen.entry(address as i64 - sp as i64).or_insert((0, word));
                    entry.0 += 1;
                    entry.1 = word;
                    values.entry(address as i64 - sp as i64).or_default().insert(word);
                }
                // The first word below the stack pointer from which 4 KiB hold only zeros.
                if address + 4096 < sp && deep_zero_top == i64::MIN {
                    let run = &bytes[index * 8..index * 8 + 4096];
                    if run.iter().all(|&byte| byte == 0) {
                        deep_zero_top = address as i64 - sp as i64;
                    }
                }
            }
        }
    }
    let mut offsets: Vec<(i64, (usize, u64))> = seen.into_iter().collect();
    offsets.sort();
    println!("words that are no number and no address, by offset from the idle stack pointer (count over {} stacks, last value):", calls * pool.len());
    for (offset, (count, word)) in offsets {
        println!("  {offset:+8}: {count:4} seen, {:4} values, last {word:#018x}", values[&offset].len());
    }
    println!("{hits} hits on {calls} calls");
    drop(engine);
}

/// The same pool and calls as the real engine, in this crate, without the overwrite, which `paint`
/// and `measure` need: how deep each thread writes below its idle stack pointer.
fn depth(calls: usize, memory_kib: u32, passes: u32, length: usize) {
    let before = tids();
    let threads = ThreadPoolBuilder::new().num_threads(LANES as usize).build().unwrap();
    let pool: Vec<u32> = tids().into_iter().filter(|tid| !before.contains(tid)).collect();
    let bytes = memory_kib as usize * 1024;
    let mut blocks = vec![Block::new(); bytes / Block::SIZE];
    let password = password_of(1, length);
    let mut key = Box::new([0u8; 32]);
    let params = Params::new(memory_kib, passes, LANES, Some(32)).unwrap();
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mem = memory();
    const PAINT: usize = 1024 * 1024;
    const PATTERN: u8 = 0xa5;
    let mut deepest = vec![0usize; pool.len()];
    for _ in 0..calls {
        let sps = idle_sps(&pool);
        let paint = vec![PATTERN; PAINT];
        for &sp in &sps {
            mem.write_all_at(&paint, (sp - 256 - PAINT) as u64).unwrap();
        }
        threads
            .install(|| argon2.hash_password_into_with_memory(&password, SALT, &mut *key, &mut blocks[..]))
            .unwrap();
        let sps = idle_sps(&pool);
        for (index, &sp) in sps.iter().enumerate() {
            let bytes = read(&mem, sp - 256 - PAINT, sp - 256);
            let depth = PAINT - bytes.iter().position(|&byte| byte != PATTERN).unwrap_or(PAINT);
            deepest[index] = deepest[index].max(depth + 256);
        }
    }
    let kib: Vec<String> = deepest.iter().map(|&depth| format!("{:.1}", depth as f64 / 1024.0)).collect();
    println!("deepest write below the idle stack pointer, KiB per thread: {kib:?}");
}

/// The real engine: paints below the 128 KiB it clears and reports what was written there.
fn real_below(calls: usize, memory_kib: u32, passes: u32, length: usize) {
    let before = tids();
    let mut engine = NativeArgon2::new(memory_kib).unwrap();
    let pool: Vec<u32> = tids().into_iter().filter(|tid| !before.contains(tid)).collect();
    let password = password_of(1, length);
    let mut key = Box::new([0u8; 32]);
    let mem = memory();
    const PAINT: usize = 1024 * 1024;
    const PATTERN: u8 = 0xa5;
    let mut deepest = vec![0usize; pool.len()];
    for _ in 0..calls {
        let sps = idle_sps(&pool);
        let paint = vec![PATTERN; PAINT];
        for &sp in &sps {
            mem.write_all_at(&paint, (sp - 256 - PAINT) as u64).unwrap();
        }
        engine.argon2id(&password, SALT, memory_kib, passes, &mut key).unwrap();
        let sps = idle_sps(&pool);
        for (index, &sp) in sps.iter().enumerate() {
            let bytes = read(&mem, sp - 256 - PAINT, sp - 256);
            let depth = PAINT - bytes.iter().position(|&byte| byte != PATTERN).unwrap_or(PAINT);
            deepest[index] = deepest[index].max(depth + 256);
        }
    }
    let kib: Vec<String> = deepest.iter().map(|&depth| format!("{:.1}", depth as f64 / 1024.0)).collect();
    println!("deepest change below the idle stack pointer after the real call, KiB per thread: {kib:?}");
}

/// A place for a debugger to stop at, with every pool thread asleep.
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn probe_stop(thread_count: usize) -> usize {
    std::hint::black_box(thread_count)
}

fn main() {
    let arguments: Vec<String> = std::env::args().collect();
    let number = |index: usize, default: usize| {
        arguments.get(index).map_or(default, |value| value.parse().unwrap())
    };
    let calls = number(2, 20);
    let memory_kib = number(3, 1024) as u32;
    let passes = number(4, 1) as u32;
    let length = number(5, 20);
    match arguments.get(1).map(String::as_str) {
        Some("scan") => real_scan(calls, memory_kib, passes, length),
        Some("depth") => depth(calls, memory_kib, passes, length),
        Some("below") => real_below(calls, memory_kib, passes, length),
        Some("secret") => {
            // Inside the isolation when the first number is 1: a Secret of `memory_kib` bytes.
            if calls == 1 {
                println!("{:?}", mhfe_core::protect::Isolation::enter());
            }
            let bytes = memory_kib as usize;
            let public = vec![0x5au8; bytes];
            let mut secret = mhfe_core::protect::Secret::with_capacity(bytes);
            secret.push(&public).unwrap();
            let address = secret.as_bytes().as_ptr() as usize;
            let name = region_of(&maps(), address).map_or(String::new(), |region| region.name.clone());
            println!(
                "secret of {bytes} bytes: read back {}, locked {}, out of dumps {}, mapping {name:?}",
                secret.as_bytes() == public,
                secret.is_locked(),
                secret.is_out_of_dumps()
            );
        }
        Some("isolated") => {
            println!("{:?}", mhfe_core::protect::Isolation::enter());
            let mut engine = NativeArgon2::new(memory_kib).unwrap();
            let mut key = [0u8; 32];
            for _ in 0..calls {
                let answer = engine.argon2id(&password_of(1, length), SALT, memory_kib, passes, &mut key);
                println!("call: {answer:?}, tag starts {:02x}{:02x}", key[0], key[1]);
            }
            drop(engine);
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        Some("word") => {
            // The word at offset `length` from each idle stack pointer, after calls with two
            // passwords in turn, with what it matches in the blocks of that password.
            let offset = length as i64;
            let before = tids();
            let mut engine = NativeArgon2::new(memory_kib).unwrap();
            let pool: Vec<u32> = tids().into_iter().filter(|tid| !before.contains(tid)).collect();
            let passwords = [password_of(1, 20), password_of(2, 20)];
            let halves: Vec<HashMap<u32, usize>> = passwords
                .iter()
                .map(|password| {
                    let params = Params::new(memory_kib, passes, LANES, Some(32)).unwrap();
                    let mut blocks = vec![Block::new(); params.block_count()];
                    let mut tag = [0u8; 32];
                    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
                        .hash_password_into_with_memory(password, SALT, &mut tag, &mut blocks[..])
                        .unwrap();
                    let mut table = HashMap::new();
                    for (index, block) in blocks.iter().enumerate() {
                        for &word in block.as_ref() {
                            table.insert(word as u32, index);
                            table.insert((word >> 32) as u32, index);
                        }
                    }
                    table
                })
                .collect();
            let mem = memory();
            let mut key = Box::new([0u8; 32]);
            for call in 0..calls {
                let which = call % 2;
                engine.argon2id(&passwords[which], SALT, memory_kib, passes, &mut key).unwrap();
                let sps = idle_sps(&pool);
                let mut line = format!("call {call} password {which}:");
                for &sp in &sps {
                    let bytes = read(&mem, (sp as i64 + offset) as usize, (sp as i64 + offset) as usize + 8);
                    let word = u64::from_ne_bytes(bytes.try_into().unwrap());
                    let found = halves[which].get(&(word as u32)).map_or(String::new(), |block| format!(" (in block {block})"));
                    line.push_str(&format!(" {word:#x}{found}"));
                }
                println!("{line}");
            }
        }
        Some("hold") => {
            let before = tids();
            let mut engine = NativeArgon2::new(memory_kib).unwrap();
            let pool: Vec<u32> = tids().into_iter().filter(|tid| !before.contains(tid)).collect();
            let password = password_of(1, length);
            let mut key = Box::new([0u8; 32]);
            let table = patterns(&password, memory_kib, passes);
            let mem = memory();
            for call in 0..calls {
                engine.argon2id(&password, SALT, memory_kib, passes, &mut key).unwrap();
                let sps = idle_sps(&pool);
                let mut hits = 0;
                for &sp in &sps {
                    let bytes = read(&mem, sp - 4096, sp + 4096);
                    scan_near("stack", sp - 4096, &bytes, &table, &mut hits, sp);
                }
                if hits > 0 {
                    println!("call {call}: {hits} hits, stack pointers {sps:x?}");
                    probe_stop(pool.len());
                    // The same memory after the engine went and its threads ended: glibc keeps
                    // the stacks for its next threads.
                    drop(engine);
                    std::thread::sleep(std::time::Duration::from_millis(300));
                    println!("threads left: {}", tids().len());
                    let mut left = 0;
                    for &sp in &sps {
                        let bytes = read(&mem, sp - 4096, sp + 4096);
                        scan_near("stack after drop", sp - 4096, &bytes, &table, &mut left, sp);
                    }
                    println!("{left} hits after the engine was dropped");
                    return;
                }
            }
        }
        Some("call") => {
            let mut engine = match NativeArgon2::new(memory_kib) {
                Ok(engine) => engine,
                Err(error) => {
                    println!("new refused: {error:?}");
                    return;
                }
            };
            let mut key = [0u8; 32];
            let answer = engine.argon2id(&password_of(1, length), SALT, memory_kib, passes, &mut key);
            println!("call: {answer:?}, tag starts {:02x}{:02x}", key[0], key[1]);
        }
        _ => panic!("usage: scan|depth|below [calls] [memory_kib] [passes] [password bytes]"),
    }
}
