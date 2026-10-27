# mhfe-core audit records

These files record reviews of mhfe-core. Each one records a reviewed snapshot, its checks and its
limits; it is an evidence report, not a certification or a proof that no other defect exists.
Audit numbers run in one sequence for this repository, and a finding keeps its ID in every later
reference.

Each audit has a Markdown report, its JSON twin in the shape of the workspace's audit schema, and a
folder `AUD-NNN-harnesses/` with the harnesses a reader can rerun. Its raw evidence (logs, command
records, checksums and the validation of the report) stays in `AUD-NNN-evidence/` on the auditor's
machine, which git ignores.

AUD-001 reviewed the earlier mhfe-core 0.1.0, which was withdrawn from crates.io; its record is not
in this repository's history.

| Audit   | Date (UTC) | Reviewed snapshot                                                                  | Result                                                                                                                                                                                                                                                                                                                                                                                                                                        | Records                                                                                                                  |
| ------- | ---------- | ---------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| AUD-002 | 2026-10-27 | `main` at `dec9c8115ff9ddbd32bb5fdd457ae9904043c966` (version 0.1.0), against MHFE specification 0.7.0 | Full audit before the release: one Medium release-blocking finding (publishing the code as 0.1.0 again collides with Cargo's cache of the withdrawn 0.1.0) and eight Low (passphrase NFKD time, a 4 GiB password cut, the stack a call needs, two CI gaps, the code-rules gate and audit records, two documentation defects). Protocol, Unicode 18.0.0 NFKD and Linux isolation hold on every case run. Updated after the publication of mhfe-core 0.1.0 from the release commit `c6eaa706866b9868cb51048d64b3d21752abce44` (tag `v0.1.0`): seven findings `verified` there by CI, the full-cost replay on the tag and the harnesses, rewritten in Rust and rerun; the owner accepted the Medium finding and the release-notes one (`accepted`), so the version stays 0.1.0. No release blocker remains. Full-cost replay from CI only. The published package, SHA-256 `d44e15ab9e3f25c1c787a0b10f6b8467441463dd57b137940a97a1deb390247d`, is the one the audit reproduced locally. | [Report](AUD-002-2026-10-27.md), [JSON](AUD-002-2026-10-27.json), [harnesses](AUD-002-harnesses/README.md) |
