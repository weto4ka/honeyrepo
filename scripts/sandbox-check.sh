#!/usr/bin/env bash
# Runs the readme-exfil scenario with no sandbox and with several wrappers, then
# prints the expected and the actual verdict for each. Linux or WSL2 only.
# Needs Python 3.11+. Wrappers whose tool is not installed are skipped.
#
# The last three rows are not sandboxes. They check that honeyrepo does NOT report
# HELD when something other than protection stopped the attack.
set -u
cd "$(dirname "$0")/.." || exit 2
export PYTHONPATH="$PWD/src${PYTHONPATH:+:$PYTHONPATH}"

if ! python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)'; then
  echo "Python 3.11 or newer is required (found: $(python3 --version 2>&1))"
  exit 2
fi

BWRAP_BASE="--ro-bind / / --dev /dev --proc /proc"
FORMAT='%-44s %-13s %-13s %-19s %s\n'
mismatches=0
errfile=$(mktemp) || exit 2
trap 'rm -f "$errfile"' EXIT

check() {  # check LABEL EXPECTED REQUIRED_TOOL WRAP
  local label="$1" expected="$2" tool="$3" wrap="$4" out actual code
  if [ -n "$tool" ] && ! command -v "$tool" >/dev/null 2>&1; then
    printf "$FORMAT" "$label" "$expected" "-" "-" "SKIPPED ($tool not installed)"
    return
  fi
  if [ -n "$wrap" ]; then
    out=$(python3 -m honeyrepo run readme-exfil --json --wrap "$wrap" 2>"$errfile")
  else
    out=$(python3 -m honeyrepo run readme-exfil --json 2>"$errfile")
  fi
  # stdout is JSON and nothing else; anything honeyrepo wrote to stderr stays in $errfile
  actual=$(printf '%s' "$out" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["verdict"], d["reason_code"])' 2>/dev/null)
  if [ -z "$actual" ]; then
    actual="ERROR -"
    printf '%s\n' "$out" | head -3 | sed 's/^/    /'
    head -3 "$errfile" | sed 's/^/    /'
  fi
  code=${actual#* }
  actual=${actual%% *}
  if [ "$actual" = "$expected" ]; then result="match"; else result="DIFFERENT"; mismatches=$((mismatches + 1)); fi
  printf "$FORMAT" "$label" "$expected" "$actual" "$code" "$result"
}

printf "$FORMAT" "wrapper" "expected" "actual" "reason" ""
check "none"                                  LEAKED       ""       ""
check "unshare --net"                         HELD         unshare  "unshare --map-root-user --net"
check "bwrap: filesystem only, network open"  LEAKED       bwrap    "bwrap $BWRAP_BASE --bind {repo} {repo} --bind {home} {home}"
check "bwrap: home folder hidden"             HELD         bwrap    "bwrap $BWRAP_BASE --bind {repo} {repo} --tmpfs {home}"
check "bwrap: network off"                    HELD         bwrap    "bwrap --unshare-net $BWRAP_BASE --bind {repo} {repo} --bind {home} {home}"
check "not a sandbox: HOME points nowhere"    LEAKED       env      "env HOME=/nonexistent"
check "not a sandbox: empty environment"      LEAKED       env      "env -i"
check "not a sandbox: wrapper fails at once"  INCONCLUSIVE false    "false"

echo
if [ "$mismatches" -eq 0 ]; then echo "All checked rows match."; else echo "$mismatches row(s) differ. Paste this whole output back."; fi
exit $((mismatches > 0))
