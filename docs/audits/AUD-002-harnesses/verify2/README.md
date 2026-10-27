# AUD-002 verify2: tree unchanged

The second verification round of audit AUD-002 of mhfe-core, as the Rust crate
`aud002-verify2-tree-unchanged`. The audit reviewed commit
`dec9c8115ff9ddbd32bb5fdd457ae9904043c966`; its fixes were verified twice on the uncommitted tree
over that commit. This harness showed that nothing changed between the rounds: no file of the
repository outside `.git`, `docs/audits`, `target` and `node_modules` is newer than a reference
file, and no file outside `docs/audits/` is untracked. It prints the reference's time in UTC, the
number of modified tracked files and the SHA-256 of `git diff`, which names the tree checked, and
exits 0 when the tree is unchanged, 1 when a file is newer or untracked, and 2 when it cannot run.

From the repository root, with `<target>` a Cargo target folder outside the repository and
`<reference>` a file written when the tree was last checked:

```sh
CARGO_TARGET_DIR=<target> cargo build --release --locked --offline \
  --manifest-path docs/audits/AUD-002-harnesses/verify2/Cargo.toml
<target>/release/aud002-verify2-tree-unchanged . <reference>
```

It needs Git; it reads no network and runs no other tool. The audit's record run used the command
record of the first round's fast checks as the reference and found no change, with the diff
SHA-256 `8d626d4acd8fe5ae7fbb440b5ac24ddc707624f1ec438b3f4aa1300c379df061`.

- At dec9c81, in a fresh clone with the harness folder copied in and a reference file written
  right after: no newer file, nothing untracked outside `docs/audits/`, an empty diff; exit 0.
- At the published release commit `c6eaa70`: the same with a reference written after the checkout
  and the first copy of the harness folder (the folder, which the check leaves out, was copied in
  again with the submodule fixes at 20:08 UTC), and the run made after the other harnesses rerun
  there had run in that clone; exit 0, `rerun-release-verify2-tree-unchanged.log` (local), built in
  `rerun-release-verify2-build.log` (local). Its use in the audit, two rounds over one uncommitted
  tree, ended when the fixes were committed.

Rewritten in Rust on 2026-10-27, at the owner's decision (TOOL-01), from the script
`tree-unchanged.sh` of this folder, which the archive `original-harnesses` (local) keeps. It lists
untracked files one by one, so that one inside an untracked folder outside `docs/audits/` is named.
