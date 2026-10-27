#!/usr/bin/env bash
# AUD-002 protocol harness: builds the adapter over mhfe-core's public API and runs four checks:
# three Python scripts against the independent implementation mhfe_ref.py, and the adapter's own
# nfkd-cost mode. Exits non-zero when any check fails.
#
#   run.sh <mhfe_spec checkout> <BIP39 english.txt> <UnicodeData.txt 18.0.0> [differential scale]
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../../../.." && pwd)"
spec="$1"
english="$2"
ucd="$3"
scale="${4:-10}"
target="${CARGO_TARGET_DIR:-$here/adapter/target}"

cargo build --release --locked --manifest-path "$here/adapter/Cargo.toml"
adapter="$target/release/aud002-protocol-adapter"
eff="$repo/vendor/eff-large-wordlist/eff_large_wordlist.txt"
normalization="$repo/tests/fixtures/unicode18-ucd/NormalizationTest.txt"

# -I keeps the user's site packages and environment out; -B writes no __pycache__ into the
# repository.
status=0
echo "== replay_vectors.py"
python3 -I -B "$here/replay_vectors.py" --vectors "$spec/vectors" --english "$english" \
  --eff "$eff" --ucd "$ucd" || status=1
echo "== unicode_check.py"
python3 -I -B "$here/unicode_check.py" --adapter "$adapter" --ucd "$ucd" \
  --normalization-test "$normalization" --english "$english" || status=1
echo "== differential.py"
python3 -I -B "$here/differential.py" --adapter "$adapter" --english "$english" --eff "$eff" \
  --vectors "$spec/vectors" --ucd "$ucd" --scale "$scale" || status=1
echo "== nfkd-cost"
"$adapter" nfkd-cost || status=1
exit "$status"
