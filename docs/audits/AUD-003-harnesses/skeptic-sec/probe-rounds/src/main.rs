//! AUD-003 skeptic probe: after a whole sequence of rounds on the real NativeArgon2, which round's H0
//! still stands on a pool stack? Public test data only. Linux x86-64.
//! Build with CARGO_PROFILE_RELEASE_LTO=thin and run from a build folder of your own:
//!   probe-rounds decrypt|encrypt <runs> <memory KiB> <passes> <gap ms between calls> [window bytes]
use std::collections::HashMap;
use std::fs::{self, File};
use std::os::unix::fs::FileExt;

use blake2::{Blake2b512, Digest};
use mhfe_core::{Argon2Engine, NativeArgon2};

const LANES: u32 = 4;

fn tids() -> Vec<u32> {
    fs::read_dir("/proc/self/task")
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_str().unwrap().parse().unwrap())
        .collect()
}

fn sp_of(tid: u32) -> Option<usize> {
    let text = fs::read_to_string(format!("/proc/self/task/{tid}/syscall")).ok()?;
    let fields: Vec<&str> = text.split_whitespace().collect();
    if fields.len() < 9 {
        return None;
    }
    usize::from_str_radix(fields[7].trim_start_matches("0x"), 16).ok()
}

fn idle_sps(pool: &[u32]) -> Vec<usize> {
    for _ in 0..4000 {
        let sps: Vec<Option<usize>> = pool.iter().map(|&tid| sp_of(tid)).collect();
        if sps.iter().all(Option::is_some) {
            std::thread::sleep(std::time::Duration::from_millis(5));
            return pool.iter().map(|&tid| sp_of(tid).unwrap()).collect();
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    panic!("the pool does not sleep");
}

fn read(mem: &File, start: usize, end: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; end - start];
    for (index, page) in bytes.chunks_mut(4096).enumerate() {
        let _ = mem.read_exact_at(page, (start + index * 4096) as u64);
    }
    bytes
}

fn h0(password: &[u8], salt: &[u8; 16], memory_kib: u32, passes: u32) -> [u8; 64] {
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
    digest.update(salt);
    digest.update(0u32.to_le_bytes());
    digest.update(0u32.to_le_bytes());
    let output = digest.finalize();
    let mut bytes = [0u8; 64];
    bytes.copy_from_slice(&output);
    bytes
}

fn text(seed: u64, length: usize) -> Vec<u8> {
    let mut state = 0x9e37_79b9_7f4a_7c15u64 ^ seed;
    (0..length)
        .map(|_| {
            state = state.wrapping_mul(0xbf58_476d_1ce4_e5b9).rotate_left(29) ^ 0x94d0_49bb;
            b'a' + (state >> 56) as u8 % 26
        })
        .collect()
}

fn main() {
    let arguments: Vec<String> = std::env::args().collect();
    let mode = arguments.get(1).map_or("decrypt", String::as_str);
    let number = |index: usize, default: usize| {
        arguments.get(index).map_or(default, |value| value.parse().unwrap())
    };
    let runs = number(2, 100);
    let memory_kib = number(3, 1024) as u32;
    let passes = number(4, 1) as u32;
    let gap_ms = number(5, 0) as u64;
    let window = number(6, 8);
    let before = tids();
    let mut engine = NativeArgon2::new(memory_kib).unwrap();
    let pool: Vec<u32> = tids().into_iter().filter(|tid| !before.contains(tid)).collect();
    let mem = File::open("/proc/self/mem").unwrap();
    let mut key = Box::new([0u8; 32]);
    // Round number to how many runs left it, and at which offsets from the sleeping stack pointer.
    let mut found: HashMap<usize, (usize, HashMap<i64, usize>)> = HashMap::new();
    let mut runs_with_any = 0;
    let mut windows_seen: HashMap<usize, usize> = HashMap::new();
    for run in 0..runs {
        let password = text(run as u64 + 1, 20);
        let salts: Vec<[u8; 16]> = (0..12)
            .map(|round| text(run as u64 * 16 + round + 1000, 16).try_into().unwrap())
            .collect();
        let order: Vec<usize> = match mode {
            "decrypt" => (0..12).rev().collect(),
            "encrypt" => (0..12).chain((0..12).rev()).collect(),
            "forward" => (0..12).collect(),
            _ => panic!("mode"),
        };
        for &round in &order {
            engine.argon2id(&password, &salts[round], memory_kib, passes, &mut key).unwrap();
            if gap_ms > 0 {
                std::thread::sleep(std::time::Duration::from_millis(gap_ms));
            }
        }
        let sps = idle_sps(&pool);
        let mut any = false;
        let mut table: HashMap<Vec<u8>, (usize, usize)> = HashMap::new();
        for (round, salt) in salts.iter().enumerate() {
            let hash = h0(&password, salt, memory_kib, passes);
            for (index, part) in hash.windows(window).enumerate() {
                table.insert(part.to_vec(), (round, index));
            }
        }
        let mut hit_rounds: HashMap<usize, Vec<i64>> = HashMap::new();
        for &sp in &sps {
            // Up to the thread's own frames only: 8 KiB above is more than all of them.
            let low = sp - 300 * 1024;
            let high = sp + 6 * 1024;
            let bytes = read(&mem, low, high);
            for (offset, part) in bytes.windows(window).enumerate() {
                if part.iter().all(|&byte| byte == 0) {
                    continue;
                }
                if let Some(&(round, index)) = table.get(part) {
                    any = true;
                    *windows_seen.entry(index).or_insert(0) += 1;
                    hit_rounds.entry(round).or_default().push((low + offset) as i64 - sp as i64);
                }
            }
        }
        for (round, offsets) in hit_rounds {
            let entry = found.entry(round).or_default();
            entry.0 += 1;
            for offset in offsets {
                *entry.1.entry(offset).or_insert(0) += 1;
            }
        }
        if any {
            runs_with_any += 1;
        }
    }
    println!("{mode}: {runs} runs, {memory_kib} KiB, {passes} passes, gap {gap_ms} ms, window {window}: {runs_with_any} runs left an H0 window");
    let mut rounds: Vec<_> = found.keys().copied().collect();
    rounds.sort_unstable();
    for round in rounds {
        let (count, offsets) = &found[&round];
        let mut offsets: Vec<_> = offsets.iter().map(|(&offset, &seen)| (offset, seen)).collect();
        offsets.sort_unstable();
        let shown: Vec<String> = offsets.iter().take(14).map(|(offset, seen)| format!("{offset:+}x{seen}")).collect();
        println!("  round {round:2}: in {count} runs, at {}{}", shown.join(" "), if offsets.len() > 14 { " ..." } else { "" });
    }
    let mut windows: Vec<_> = windows_seen.into_iter().collect();
    windows.sort_unstable();
    println!("  windows of H0 seen (index x count): {windows:?}");
}
