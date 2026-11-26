# AUD-006 harnesses

The harnesses of audit AUD-006 of mhfe-core, reviewed commit
`2abcf472288d5051394f51ee22b828ed6fac17de`, remediation commit
`32651c2eaf540c647bd93c91a6932638accdc9c5`. Each is a crate of its own with its own lockfile; run
it from its folder.

- [stack-need](stack-need/README.md): the least thread stack on which each public call that clears
  the stack runs, against the 144 KiB the crate documents. Exit code 0 when every call fits.
