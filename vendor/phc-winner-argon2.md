# Vendored Argon2 reference implementation

`vendor/phc-winner-argon2/` holds the reference C implementation of Argon2 by Daniel Dinu, Dmitry
Khovratovich, Jean-Philippe Aumasson and Samuel Neves. It is the Argon2 engine of every native
build: `build.rs` compiles it for every native target, and a WebAssembly host can compile the same
files with Emscripten from the one list, `src/engine/argon2-sources.txt`.

## Source

| Item                  | Value                                                                    |
| --------------------- | ------------------------------------------------------------------------ |
| Repository            | https://github.com/P-H-C/phc-winner-argon2                               |
| Commit                | `f57e61e19229e23c4445b85494dbf7c07de721cb`                               |
| Commit date           | 2021-06-25, "Merge pull request #321 from bittorf/fix-spelling-mistakes" |
| Branch state          | the commit was the head of `master` when it was vendored on 2026-09-29   |
| Last upstream release | tag `20190702`, commit `62358ba2123abd17fccf2a108a301d4b52c01a7c`        |
| Vendored              | `include/`, `src/`, `LICENSE`, `README.md`                               |

The files were exported with `git archive` from a clone at that commit, and each file was checked
against the commit with `git hash-object`. They are unmodified. MHFE needs no patch; if one is ever
needed, it goes into a separate, documented patch file next to this document instead of an edit of
the vendored files.

Between the release `20190702` and the vendored commit, the vendored files changed only in comment
URLs (`http` to `https`), in preprocessor guards for Windows and MinGW, and in a spelling fix. The
algorithm did not change.

## Files that are compiled

- Every build: `src/argon2.c`, `src/core.c`, `src/encoding.c`, `src/thread.c`,
  `src/blake2/blake2b.c`, and MHFE's own wrapper, the separate file `src/engine/argon2_wrap.c`.
  Rust calls only its `mhfe_argon2_ctx()`, and `core.c` calls its `fill_segment()`, which runs the
  vendored one, renamed by a `-D` define when it is compiled; both clear the stack the vendored
  code used.
- Native `x86_64`: `src/opt.c`, compiled twice, with SSE2 and with SSSE3; the wrapper runs the
  SSSE3 copy where the processor has SSSE3. Other native architectures, including ARM64, and an
  Emscripten build: `src/ref.c`.
- Not compiled: `src/bench.c`, `src/genkat.c`, `src/genkat.h`, `src/run.c` and `src/test.c`, which
  are upstream's own benchmark, test and command-line programs.

## Licence

The authors release the code under CC0 1.0 or the Apache License 2.0, at the user's option; both
texts are in `phc-winner-argon2/LICENSE`. MHFE uses the code under the **Apache License 2.0**:
releases ship that licence text with the code, and any change to a vendored file would be kept as a
separate patch file that says what was changed and why.

## SHA-256 of every vendored file

```text
ac36638bcfcedb75441a5daeeaf4ef75b565911712583c272830e9fa7fddb590  LICENSE
1919b5242169e14eea169b00f0444d5a3185e2bd13883dac962d73754313b6d7  README.md
25ed629feca91ca9d361441160c6fbc10318bb0fb3757555b418ed47b705b35b  include/argon2.h
b1289ec7134e8502e9113396fdac89402bf2575ee1b35e33fb7410f2fb63bb6d  src/argon2.c
34f00696758d816cb7991d78b625343725dbb87282e0d6a63625d21263cc8bfb  src/bench.c
ec9884fe834c30eb362f0cef3432a43a5c496b0d6d1d637a5a590a45bec4d79c  src/blake2/blake2-impl.h
196cd9adf0660474ea04cb686c122f3ca8c758445c5ff0806f438e6412ac8423  src/blake2/blake2.h
7eb2f3faac14c532fb75f645f518686f3ef0db4c7b9849a1ffc73d262b596281  src/blake2/blake2b.c
38772a3fc29db218a1833b8fa326cb95f98fdc2cda1cbcbaede928a2d8d32b41  src/blake2/blamka-round-opt.h
8d5fc886bbc0b55af10ac6f1e9a5995a4e8d4abace46642fb1832c84d38c3007  src/blake2/blamka-round-ref.h
d6ddc9e28c51d2c3b0d542c0c4678c4d9d788da048e4f557166030d0ef62618b  src/core.c
32f6ab8c0c313d9336d2731a001426b68d246bba5b362fabeaf593c333da7d37  src/core.h
7b9a0c019abc6fca7e6e0a9abd2f7b22a885f8831827cfbd4bfd4502dd9f7806  src/encoding.c
a4e0681ef4b0eb229a35760b603b7a32e9019cfe98c31732f747f087e5e39828  src/encoding.h
ff441d21a2f2191556ec2e1e147a5f40f9d1d4483c9fd07fb9d186c9297f5d65  src/genkat.c
3023b7698a8b63d0b31dfd959504fb7a47161be10eb2d1b4fb73994e7d2dbc83  src/genkat.h
f8776e4a2f824beed34634f3024a95fdbdbaedc2d17a990b752a89a3f963227a  src/opt.c
9ac347fd8dc737af69bbb93d56ac8b4ab5488152f606880c8d7fc4592e207647  src/ref.c
88e26b56a36d411e94a6605083d00dca9f54d0af34bd9a0f35109d07628c66eb  src/run.c
ec518844e823fb6a1bd38f79f2b5d1bbddf23f490c0a343c450aa8e3f5af5988  src/test.c
af2ab481fcf5ef00f1b2deb346bda3642797b417fc0ed98bfb7ae80e716f90d1  src/thread.c
650e713fb584de2e6aeb307e64228f95cef733ea667faa0bb111960aaace30ef  src/thread.h
```

To check the vendored files against this list, run from the repository root:

````sh
sed -n '/^```text$/,/^```$/p' vendor/phc-winner-argon2.md | grep -v '^```' \
  | (cd vendor/phc-winner-argon2 && sha256sum --check)
````

## Review of upstream issues and pull requests

On 2026-09-29 all 112 issues and pull requests opened upstream since the `20190702` release (the
newest from 2026-08-02) were read. Most are questions, bindings, build-system changes and README
links. The points that matter for MHFE:

- **Maintenance.** The upstream organiser confirmed in #378 (2024) that the repository is no longer
  maintained because the algorithm and API are frozen. MHFE therefore pins one commit and keeps any
  future change as its own documented patch.
- **Correctness.** No report shows a wrong hash from the library code. The only such report, #329
  (ARM64), was a newline added by `echo` to the password.
- **Error and wiping paths.** #298 concerns the encoded-string output, which MHFE does not use; on
  an Argon2 error, `argon2_hash` wipes its output buffer without copying it. #297 and #299 concern
  the upstream command-line program `run.c`, which MHFE does not compile. #283 reports `free(NULL)`,
  which is valid C.
- **Validation order.** #300 and #301 change the order of parameter checks. MHFE validates its own
  parameters before calling Argon2 and always uses four lanes.
- **Threads.** #331 proposes returning from the thread function instead of calling `pthread_exit`,
  to avoid a `libgcc_s` dependency on minimal systems. Both work; MHFE keeps upstream's code.
- **CPU instructions.** #308 is a crash with an invalid instruction after `opt.c` was compiled for a
  newer processor than the one running it; the failing virtual machine offered SSE2 and SSE3 but not
  SSSE3. This is why the native `x86_64` program never assumes SSSE3: it checks the processor and
  falls back to the SSE2 copy of `opt.c`.

## Limits worth knowing

- On 32-bit targets, including WebAssembly, `ARGON2_MAX_MEMORY_BITS` in `include/argon2.h` limits
  memory to `2^21` KiB, exactly 2 GiB. A 32-bit WebAssembly host therefore supports memory level 0
  only; a larger level fails with `ARGON2_MEMORY_TOO_MUCH` before any memory is allocated. On
  64-bit targets the limit is `2^32 - 1` KiB, which covers every MHFE memory level.
- `secure_wipe_memory` uses `explicit_bzero` with glibc and `SecureZeroMemory` on Windows. Where
  neither exists and `memset_s` is not a macro, as with Emscripten, it calls `memset` through a
  volatile function pointer so that the compiler cannot drop the wipe.
