#!/usr/bin/env bash
# Runs one command of audit AUD-003 and keeps its evidence in the evidence folder: <name>.log with
# its output and <name>.command.json with the exact command, the UTC start and end, the exit code
# and the SHA-256 of the log. Exits with the command's exit code.
#
#   docs/audits/AUD-003-harnesses/run-logged.sh <evidence folder> <name> <command> [arguments...]
set -euo pipefail

evidence="$1"
name="$2"
shift 2
mkdir -p "$evidence"
start="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
set +e
"$@" > "$evidence/$name.log" 2>&1
code=$?
set -e
end="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
sum="$(sha256sum "$evidence/$name.log" | cut -d' ' -f1)"
python3 -I - "$evidence/$name.command.json" "$start" "$end" "$code" "$sum" "$@" <<'PY'
import json, sys
path, start, end, code, digest, *command = sys.argv[1:]
json.dump({"command": command, "startUtc": start, "endUtc": end, "exitCode": int(code),
           "logSha256": digest}, open(path, "w"), indent=2)
PY
echo "$name: exit $code ($start to $end)"
exit "$code"
