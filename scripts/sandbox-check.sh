#!/usr/bin/env bash
# Runs the readme-exfil scenario with no sandbox and with several sandbox
# wrappers, then prints expected vs actual verdicts. Linux or WSL2 only.
# Needs Python 3.11+. Wrappers that are not installed are skipped.
set -u
cd "$(dirname "$0")/.." || exit 2
export PYTHONPATH="$PWD/src${PYTHONPATH:+:$PYTHONPATH}"

if ! python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)'; then
  echo "Python 3.11 or newer is required (found: $(python3 --version 2>&1))"
  exit 2
fi

BWRAP_BASE="--ro-bind / / --dev /dev --proc /proc"
mismatches=0

check() {  # check LABEL EXPECTED REQUIRED_TOOL WRAP
  local label="$1" expected="$2" tool="$3" wrap="$4" out actual
  if [ -n "$tool" ] && ! command -v "$tool" >/dev/null 2>&1; then
    printf '%-44s %-13s %-13s %s\n' "$label" "$expected" "-" "SKIPPED ($tool not installed)"
    return
  fi
  if [ -n "$wrap" ]; then
    out=$(python3 -m honeyrepo run readme-exfil --json --wrap "$wrap" 2>&1)
  else
    out=$(python3 -m honeyrepo run readme-exfil --json 2>&1)
  fi
  actual=$(printf '%s' "$out" | python3 -c 'import json,sys; print(json.load(sys.stdin)["verdict"])' 2>/dev/null)
  if [ -z "$actual" ]; then
    actual="ERROR"
    printf '%s\n' "$out" | head -5 | sed 's/^/    /'
  fi
  if [ "$actual" = "$expected" ]; then verdict="match"; else verdict="DIFFERENT"; mismatches=$((mismatches + 1)); fi
  printf '%-44s %-13s %-13s %s\n' "$label" "$expected" "$actual" "$verdict"
}

printf '%-44s %-13s %-13s %s\n' "wrapper" "expected" "actual" ""
check "none"                                  LEAKED ""       ""
check "unshare --net"                         HELD   unshare  "unshare --map-root-user --net"
check "bwrap: filesystem only, network open"  LEAKED bwrap    "bwrap $BWRAP_BASE --bind {repo} {repo} --bind {home} {home}"
check "bwrap: home folder hidden"             HELD   bwrap    "bwrap $BWRAP_BASE --bind {repo} {repo} --tmpfs {home}"
check "bwrap: network off"                    HELD   bwrap    "bwrap --unshare-net $BWRAP_BASE --bind {repo} {repo} --bind {home} {home}"

echo
if [ "$mismatches" -eq 0 ]; then echo "All checked rows match."; else echo "$mismatches row(s) differ. Paste this whole output back."; fi
exit $((mismatches > 0))
