#!/usr/bin/env bash
# Builds probe-stack under one host profile and scans what the real engine leaves behind.
#   docs/audits/AUD-003-harnesses/sec/run-matrix.sh <label> [ENV=VALUE ...]
# Each ENV=VALUE overrides the release profile, such as CARGO_PROFILE_RELEASE_LTO=thin. The build
# goes to $CARGO_TARGET_DIR/<label>. Exits non-zero when the build fails, the scan does not finish,
# it finds none of the probe's own copies of the secrets, or a word of a secret stays on a thread's
# stack.
set -euo pipefail
label=$1
shift
here=$(cd "$(dirname "$0")" && pwd)
target="${CARGO_TARGET_DIR:?set CARGO_TARGET_DIR}/$label"
(cd "$here/probe-stack" && env "$@" CARGO_TARGET_DIR="$target" cargo build --offline --locked --release 2>&1 | tail -1)
out=$(timeout 300 "$target/release/probe-stack" scan 40 1024 1 20 2>&1)
echo "$out" | grep -qE 'hits on' # the line of a scan that finished
# The probe's own copies of the secrets, which a scan that read the memory finds.
controls=$(echo "$out" | sed -nE 's/^([0-9]+) hits in the writable mappings after the first call$/\1/p')
[ "${controls:-0}" -gt 0 ]
found=$(echo "$out" | grep -cE 'thread [0-9]+ stack: ' || true)
echo "$label scan 40 calls: $(echo "$out" | grep -E 'hits on') / lines of stack hits: $found"
echo "$out" | { grep -E 'thread [0-9]+ stack: ' || true; } | sed -E 's/call [0-9]+ thread [0-9]+ stack: //; s/highest at [^,]*, sp [^,]*, //' | sort | uniq -c | sort -rn | head -20
[ "$found" -eq 0 ]
