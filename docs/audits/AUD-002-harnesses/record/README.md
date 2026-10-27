# AUD-002 record check

Checks the record of audit AUD-002 of mhfe-core before it is committed, as the Rust crate
`aud002-validate-record`. The record is `docs/audits/AUD-002-2026-10-27.md` and its JSON twin; the
audit reviewed commit `dec9c8115ff9ddbd32bb5fdd457ae9904043c966`, and the published release
commit `c6eaa706866b9868cb51048d64b3d21752abce44` holds neither the record nor these harnesses,
which stand untracked over it. Ten checks:

- `json-schema`: the JSON record validates against the workspace's `audit-report.schema.json`
  (draft 2020-12). The keywords that schema uses are written out in `src/schema.rs` instead of a
  JSON Schema crate, which the local Cargo cache does not hold; a keyword not written out there
  fails the check, so that a later schema is never applied in part.
- `json-duplicate-keys`: no object of the JSON record has a key twice.
- `finding-ids-in-both-records`: the Markdown register, headings and remediation table and the JSON
  findings and remediation hold the same findings, with the same category, kind, severity, status,
  title and release blocking; each ID carries its category, and no ID appears twice.
- `finding-numbering`: the findings are numbered per category in the order they are presented.
- `metadata-agree`: the commit, date, title and reviewer agree.
- `committed-links-resolve`: every link of the committed audit Markdown files resolves to a file
  inside the repository that git does not ignore; no link leaves the repository.
- `local-evidence-marked`: every reference to the local evidence folder or one of its files is
  marked "(local)", or `"local": true` in the JSON.
- `cited-log-hashes`: every log a record cites with a SHA-256 exists and has it.
- `privacy-and-language`: the audit files hold no login name or home folder of the machine that
  runs the check, no home folder but `/home/user/`, no time outside UTC, and no non-English script
  in Markdown or JSON.
- `evidence-not-staged`: git has no evidence file staged or tracked, and ignores the evidence
  folder.

From the repository root, with `<target>` a Cargo target folder outside the repository and the
schema from a checkout of `multi-chain-wallet-tools`:

```sh
CARGO_TARGET_DIR=<target> cargo build --release --locked --offline \
  --manifest-path docs/audits/AUD-002-harnesses/record/Cargo.toml
<target>/release/aud002-validate-record \
  <multi-chain-wallet-tools>/docs/audit-report.schema.json [<result.json>]
```

It needs Git, the record files, the evidence folder (local) for the hashes, and `LOGNAME` or `USER`
and `HOME` set. It prints `PASS` or `FAIL` per check and `<n> of 10 checks pass`, writes the result
as JSON when a path is given, and exits 0 when every check passes, 1 when one fails and 2 when it
cannot run.

- At dec9c81, with only the harness folder copied in, the record is missing: exit 2.
- Run in the repository at the release commit, with the record untracked over it: ten `PASS` lines
  and exit 0 once the record is final; a record still being edited fails the checks it breaks.
- At the earlier release commit `2cfaa229fbe0fb046ecdb2d45291b380da4a12bf`, on 2026-10-27, before
  the record's update for it: exit 1, eight checks passing. `local-evidence-marked` found five
  references not marked local, in the READMEs of `api/`, `skeptic-bld-gate/` and `verify/`, and
  `cited-log-hashes` 30 logs rerun after the record's last update. With some references marked, a
  second run gave exit 1 again, eight checks passing: one reference left in `api/`, and 43 logs not
  as cited: `rerun-release-validate-record-after-readmes.log` (local). The first run's log was
  replaced by the run below.
- At the published release commit `c6eaa706866b9868cb51048d64b3d21752abce44`, in the repository,
  before the record's update for it: built with `--locked`, exit 0,
  `rerun-release-validate-record-build.log` (local); exit 1, nine checks passing, in
  `rerun-release-validate-record.log` (local): `cited-log-hashes` found the logs rerun at that
  commit or renamed since the earlier draft of the record. The record's final run writes
  `report-validation.json` (local), and its log is `release-validate-record.log` (local).

Rewritten in Rust on 2026-10-27, at the owner's decision (TOOL-01), from the script
`validate-record.py` of this folder, which the archive `original-harnesses` (local) keeps; the
rewrite removes the Python dependency without a hash-pinned requirements file (finding H6 of the
final review) and the long lines (H7). The checks are the same, with two made able to fail: finding
IDs are compared before a map removes duplicates, and a link that leaves the repository is refused.
