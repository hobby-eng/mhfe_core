# AUD-006 stack-need harness

Measures, for audit AUD-006 of reviewed commit `2abcf472288d5051394f51ee22b828ed6fac17de`, the
least thread stack on which each public call that clears the stack runs: reading a phrase, encoding
a password, making a repair card and repairing a container. At the reviewed commit the crate's
documents said such a call needs about 140 KiB; the remediation says up to 144 KiB.

Inputs: none; the container is made from fixed public entropy.

Run from this folder, in both profiles:

```sh
cargo run --release
cargo run
```

Each prints one line per call, such as `repair: Some(140) KiB`, the least size in steps of 4 KiB at
which a child process's thread of that size made the call. Exit code 0 when every call fits in
144 KiB, 1 otherwise. Measured at the remediation commit: 136, 136, 140 and 140 KiB in the release
profile, 136, 136, 144 and 144 KiB in the debug profile, on Linux x86-64 with Rust 1.99.1.
