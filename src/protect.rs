//! Protection of secrets, by the secret-protection-core crate: [`Secret`], the buffer every secret
//! of this crate lives in, which a host uses for its own secrets too, such as a typed line or a
//! row of output, and [`SecretError`], its refusal; [`Isolation`], what the process does against a
//! secret leaving it; and, in a native build, `write_secret`, the output of a secret. What each
//! does on each system, and the rest of that crate, such as the options of isolation, a worker
//! process and hidden terminal input, is in its own documentation; a host that needs the rest takes
//! exactly the version this crate pins, 0.2.0.

#[cfg(not(target_arch = "wasm32"))]
pub use secret_protection_core::write_secret;
pub use secret_protection_core::{Isolation, Secret, SecretError};
