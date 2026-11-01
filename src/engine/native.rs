//! Argon2id on RustCrypto's `argon2`, with one work area for every round and four threads of its
//! own, which it leaves clean after every call.

use argon2::{Algorithm, Argon2, Block, Params, Version};
use rayon::{ThreadPool, ThreadPoolBuilder};
use zeroize::Zeroize;

use super::{Argon2Engine, KEY_BYTES, SALT_BYTES};
use crate::os::Pages;
use crate::{Error, stack};

// A native 32-bit build cannot run even level 0: Rust refuses a slice of 2 GiB or more there (it
// may not exceed isize::MAX). Such a build is refused here rather than failing at the first
// operation. A WebAssembly build has no native engine: its host supplies Argon2id.
#[cfg(not(target_pointer_width = "64"))]
compile_error!("the native Argon2id engine needs a 64-bit target: suite 3 needs at least 2 GiB");

/// Argon2id lanes, fixed by the specification, and as many threads to run them.
const LANES: u32 = 4;

/// The stack of each thread: std's default, far above [`stack::CLEARED_BYTES`].
const THREAD_STACK_BYTES: usize = 2 * 1024 * 1024;

/// A thread the system refuses, and whatever RustCrypto refuses, as [`Error::Argon2Failed`] reports
/// them: its code has the reference implementation's numbering whichever engine sets it, and these
/// are the values of argon2.h. RustCrypto's own errors have no numbers.
const ARGON2_THREAD_FAIL: i32 = -33;
const ARGON2_INCORRECT_PARAMETER: i32 = -25;

/// RustCrypto's Argon2id, its four lanes on four threads of its own, the engine of every native
/// build. Its work area lies on memory pages of its own, kept out of core dumps and out of a child
/// process where the system allows it. After every call the area is wiped and each thread
/// overwrites its stack.
pub struct NativeArgon2 {
    work_area: Pages,
    threads: ThreadPool,
}

impl NativeArgon2 {
    /// Reserves `memory_kib` KiB once, for every call, and starts the four threads; a call with
    /// more memory is [`Error::OutOfMemory`], as is a reservation the system refuses, and a thread
    /// it refuses is [`Error::Argon2Failed`]. The host encodes the password first, so that a
    /// refused one costs no reservation. It estimates no free memory: a reservation the system
    /// grants can still end the process when it is used (overcommit; the OOM or low-memory killer,
    /// jetsam), so the host checks free memory before (the specification's "Resources").
    ///
    /// The threads start here, so a host calls [`crate::protect::Isolation::enter`] first: it
    /// needs a process of one thread to hold for the whole process, and the threads inherit it
    /// from the thread that makes the engine, not from the one that calls `argon2id`. So where it
    /// holds for the calling thread only (Android, or Linux with other threads), that thread makes
    /// the engine. They end soon after the engine is dropped, not by the time the drop returns.
    ///
    /// The area is locked where the system's limit on locked memory holds all of it, which also
    /// commits it: on Linux, Android, macOS and iOS when RLIMIT_MEMLOCK is at least its size, on
    /// Windows when the working set could grow by its size.
    pub fn new(memory_kib: u32) -> Result<Self, Error> {
        let bytes = memory_kib as usize * 1024;
        let work_area = Pages::work_area(bytes).ok_or(Error::OutOfMemory)?;
        // A pool of its own: the global one would take a thread per processor and outlive this
        // engine. An explicit number and stack size also leave RAYON_NUM_THREADS and
        // RUST_MIN_STACK without a say.
        let threads = ThreadPoolBuilder::new()
            .num_threads(LANES as usize)
            .stack_size(THREAD_STACK_BYTES)
            .build()
            .map_err(|_| Error::Argon2Failed {
                code: ARGON2_THREAD_FAIL,
            })?;
        Ok(Self { work_area, threads })
    }

    /// Whether the system keeps the work area in memory, never in swap.
    pub fn is_locked(&self) -> bool {
        self.work_area.is_locked()
    }

    /// One call of Argon2id, on the threads, so that the lanes and the first and last hash run
    /// there and the caller's stack stays out of it. What it leaves is [`NativeArgon2::argon2id`]'s
    /// to clear.
    fn compute(
        &mut self,
        password: &[u8],
        salt: &[u8; SALT_BYTES],
        memory_kib: u32,
        passes: u32,
        key: &mut [u8; KEY_BYTES],
    ) -> Result<(), Error> {
        let refused = |_| Error::Argon2Failed {
            code: ARGON2_INCORRECT_PARAMETER,
        };
        let blocks = blocks(&mut self.work_area);
        // A block is 1 KiB.
        if memory_kib as usize > blocks.len() {
            return Err(Error::OutOfMemory);
        }
        let params = Params::new(memory_kib, passes, LANES, Some(KEY_BYTES)).map_err(refused)?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        // In a frame of its own, so that the clearing of the thread that holds H0 and the tag
        // starts above everything the hash wrote.
        self.threads
            .install(|| {
                stack::cleared(|| {
                    argon2.hash_password_into_with_memory(password, salt, key, blocks)
                })
            })
            .map_err(refused)
    }

    /// Overwrites the whole area with zeros.
    fn wipe(&mut self) {
        // zeroize writes through volatile stores, which the compiler may not remove even though
        // the memory is not read again before it is given back.
        for block in blocks(&mut self.work_area) {
            AsMut::<[u64]>::as_mut(block).zeroize();
        }
    }
}

// A deliberate copy of the trait's signature, which an implementation repeats.
impl Argon2Engine for NativeArgon2 {
    fn argon2id(
        &mut self,
        password: &[u8],
        salt: &[u8; SALT_BYTES],
        memory_kib: u32,
        passes: u32,
        key: &mut [u8; KEY_BYTES],
    ) -> Result<(), Error> {
        let result = self.compute(password, salt, memory_kib, passes, key);
        // RustCrypto wipes neither the area nor the stacks, where it leaves its hashes and the
        // blocks of its compression. A pool thread lives on, so nothing else ever clears them.
        self.threads.broadcast(|_| stack::overwrite());
        self.wipe();
        result
    }
}

/// The work area as Argon2 blocks.
#[allow(
    unsafe_code,
    reason = "RustCrypto takes its memory as Blocks, and bytes become Blocks through a raw pointer"
)]
fn blocks(work_area: &mut Pages) -> &mut [Block] {
    let area = work_area.as_mut_slice();
    let count = area.len() / Block::SIZE;
    // SAFETY: pages start on a page boundary, which meets a Block's alignment of 64; `count`
    // Blocks fit in the area; a Block is 128 u64, of which every bit pattern is valid; and the
    // result borrows the pages exclusively, as `area` did.
    unsafe { std::slice::from_raw_parts_mut(area.as_mut_ptr().cast::<Block>(), count) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::hex;

    const PASSWORD: &[u8] = b"public test password";
    const SALT: &[u8; SALT_BYTES] = b"0123456789abcdef";

    /// MHFE's call at small costs, which the host passes with each call, on one engine that
    /// reserved the most of them. The longest password is there because H0's input takes a second
    /// BLAKE2b block from 73 bytes on, and no published vector is that long. The tags were computed
    /// with OpenSSL through Python cryptography 46.0.5, an implementation independent of
    /// RustCrypto's.
    #[test]
    fn gives_the_openssl_tags_at_small_costs() {
        let mut engine = NativeArgon2::new(1024).unwrap();
        for (password, memory_kib, passes, tag) in [
            (
                PASSWORD,
                1024,
                1,
                "e0e8eba33f1404a83c911a324d9b49db83dae755f2bdfb4b63043ca5b7125df2",
            ),
            (
                PASSWORD,
                64,
                3,
                "7f73efe06ad313d2fc8e9b7405e79d9afc5e9ced5647136b4675d1df181bc3fe",
            ),
            (
                &[b'a'; crate::Password::MAX_BYTES],
                64,
                1,
                "70fa34245ee10261113e742cac80b1a5f80fb28a72dd40f184dd9547750053fb",
            ),
        ] {
            let mut key = [0u8; KEY_BYTES];
            engine
                .argon2id(password, SALT, memory_kib, passes, &mut key)
                .unwrap();
            assert_eq!(key[..], hex(tag));
        }
    }

    #[test]
    fn a_call_with_more_memory_than_reserved_is_refused() {
        let mut engine = NativeArgon2::new(64).unwrap();
        let mut key = [0u8; KEY_BYTES];
        assert_eq!(
            engine.argon2id(PASSWORD, SALT, 128, 1, &mut key),
            Err(Error::OutOfMemory)
        );
        assert_eq!(engine.argon2id(PASSWORD, SALT, 64, 1, &mut key), Ok(()));
    }

    #[test]
    fn a_call_leaves_the_work_area_wiped_and_the_next_gives_the_same_tag() {
        let mut engine = NativeArgon2::new(64).unwrap();
        let mut first = [0u8; KEY_BYTES];
        let mut second = [0u8; KEY_BYTES];
        engine.argon2id(PASSWORD, SALT, 64, 1, &mut first).unwrap();
        assert!(engine.work_area.as_slice().iter().all(|&byte| byte == 0));
        engine.argon2id(PASSWORD, SALT, 64, 1, &mut second).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn a_refused_call_carries_the_reference_code_and_leaves_the_work_area_wiped() {
        let mut engine = NativeArgon2::new(64).unwrap();
        engine.work_area.as_mut_slice().fill(0xff);
        let mut key = [0u8; KEY_BYTES];
        assert_eq!(
            engine.argon2id(PASSWORD, SALT, 64, 0, &mut key),
            // ARGON2_INCORRECT_PARAMETER in the reference code's argon2.h.
            Err(Error::Argon2Failed { code: -25 })
        );
        assert!(engine.work_area.as_slice().iter().all(|&byte| byte == 0));
    }

    /// Whether the stack below this frame holds one of `words`, down to twice what a thread clears,
    /// so that a block written below the cleared part counts too. It is read through the kernel,
    /// since Rust may not read memory that no value was written to.
    #[cfg(target_os = "linux")]
    #[inline(never)]
    fn stack_holds_one_of(words: &std::collections::HashSet<u64>) -> bool {
        use std::os::unix::fs::FileExt;

        let frame = 0u64;
        let end = std::hint::black_box(&raw const frame) as u64;
        let mut stack = vec![0u8; 2 * stack::CLEARED_BYTES];
        let start = end - stack.len() as u64;
        std::fs::File::open("/proc/self/mem")
            .unwrap()
            .read_exact_at(&mut stack, start)
            .unwrap();
        let (stack_words, _) = stack.as_chunks();
        stack_words
            .iter()
            .any(|word| words.contains(&u64::from_ne_bytes(*word)))
    }

    /// How many of the engine's threads hold one of `words` on their stacks.
    #[cfg(target_os = "linux")]
    fn threads_holding(engine: &NativeArgon2, words: &std::collections::HashSet<u64>) -> usize {
        let held = engine.threads.broadcast(|_| stack_holds_one_of(words));
        held.into_iter().filter(|&held| held).count()
    }

    /// The words of the blocks stand for all that RustCrypto leaves on a stack: at one pass the
    /// area holds each block as the compression left it. The stacks are searched for these words
    /// and not for any byte that is not zero, because a thread's idle loop writes below the frame
    /// between two broadcasts, in a debug build deeper than the compression does in a release one.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_threads_do_the_work_and_keep_no_block_on_their_stacks() {
        let mut engine = NativeArgon2::new(8192).unwrap();
        let mut key = [0u8; KEY_BYTES];
        engine.compute(PASSWORD, SALT, 8192, 1, &mut key).unwrap();
        let area = blocks(&mut engine.work_area);
        let words = area.iter().flat_map(Block::as_ref).copied().collect();
        // The thread that runs the hash clears its own stack, and a thread that wakes late may
        // miss a call, though not a hundred.
        let worked = (0..100).any(|_| {
            engine.compute(PASSWORD, SALT, 8192, 1, &mut key).unwrap();
            threads_holding(&engine, &words) >= LANES as usize - 2
        });
        assert!(worked);
        engine.argon2id(PASSWORD, SALT, 8192, 1, &mut key).unwrap();
        assert_eq!(threads_holding(&engine, &words), 0);
    }
}
