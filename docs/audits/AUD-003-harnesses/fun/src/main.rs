//! AUD-003, fun reviewer: what a host of `NativeArgon2` sees, in the published 0.1.0 and in the
//! audited commit, side by side.
//!
//! - `traits` prints the auto traits of `NativeArgon2` and `Mhfe<NativeArgon2>` of both versions.
//! - `call published` and `call audited` make one call of Argon2id at 1 MiB on an engine of that
//!   version, to be run under `RUST_MIN_STACK`.

use std::error::Error;
use std::marker::PhantomData;
use std::panic::{RefUnwindSafe, UnwindSafe};

const PASSWORD: &[u8] = b"public test password";
const SALT: &[u8; 16] = b"0123456789abcdef";
const MEMORY_KIB: u32 = 1024;

/// What a type does not implement. An inherent constant of [`Implemented`], which exists only when
/// the bound holds, wins over these defaults.
#[allow(
    dead_code,
    reason = "a default is read only for a type without that trait"
)]
trait NotImplemented {
    const SEND: bool = false;
    const SYNC: bool = false;
    const UNPIN: bool = false;
    const UNWIND_SAFE: bool = false;
    const REF_UNWIND_SAFE: bool = false;
}

/// Asks which auto traits `T` has.
struct Implemented<T>(PhantomData<T>);

impl<T> NotImplemented for Implemented<T> {}

impl<T: Send> Implemented<T> {
    const SEND: bool = true;
}

impl<T: Sync> Implemented<T> {
    const SYNC: bool = true;
}

impl<T: Unpin> Implemented<T> {
    const UNPIN: bool = true;
}

impl<T: UnwindSafe> Implemented<T> {
    const UNWIND_SAFE: bool = true;
}

impl<T: RefUnwindSafe> Implemented<T> {
    const REF_UNWIND_SAFE: bool = true;
}

/// Prints the auto traits of a type under `label`.
macro_rules! auto_traits {
    ($label:expr, $type:ty) => {
        println!(
            "{}: Send={} Sync={} Unpin={} UnwindSafe={} RefUnwindSafe={}",
            $label,
            Implemented::<$type>::SEND,
            Implemented::<$type>::SYNC,
            Implemented::<$type>::UNPIN,
            Implemented::<$type>::UNWIND_SAFE,
            Implemented::<$type>::REF_UNWIND_SAFE,
        );
    };
}

/// Makes one call on an engine of the crate `$core` and prints the start of its tag.
macro_rules! one_call {
    ($core:ident) => {{
        use $core::Argon2Engine;
        let mut engine = $core::NativeArgon2::new(MEMORY_KIB)?;
        let mut key = [0u8; 32];
        engine.argon2id(PASSWORD, SALT, MEMORY_KIB, 1, &mut key)?;
        println!("tag starts {:02x?}", &key[..4]);
    }};
}

fn main() -> Result<(), Box<dyn Error>> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let arguments: Vec<&str> = arguments.iter().map(String::as_str).collect();
    match arguments[..] {
        ["traits"] => {
            auto_traits!("0.1.0 NativeArgon2", core_published::NativeArgon2);
            auto_traits!(
                "0.1.0 Mhfe<NativeArgon2>",
                core_published::Mhfe<core_published::NativeArgon2>
            );
            auto_traits!("audited NativeArgon2", core_audited::NativeArgon2);
            auto_traits!(
                "audited Mhfe<NativeArgon2>",
                core_audited::Mhfe<core_audited::NativeArgon2>
            );
        }
        ["call", "published"] => one_call!(core_published),
        ["call", "audited"] => one_call!(core_audited),
        _ => return Err("traits | call published | call audited".into()),
    }
    Ok(())
}
