#!/usr/bin/env bash
set -euo pipefail

BAIT_LOG="${ISOL8R_BAIT_LOG:-/app/logs/bait.log}"
FLAG_TARGETS=(
  "/root/real_flag.txt"
  "/opt/isol8r/data/real_flag.txt"
  "$(cd "$(dirname "${BASH_SOURCE[0]}")"/../../data && pwd)/real_flag.txt"
)

mkdir -p "$(dirname "${BAIT_LOG}")" 2>/dev/null || true
printf '[INFO] readflag_alt invoked by %s at %s\n' "${USER:-unknown}" "$(date '+%Y-%m-%d %H:%M:%S')" >> "${BAIT_LOG}"

for candidate in "${FLAG_TARGETS[@]}"; do
  if [[ -r "${candidate}" ]]; then
    exec 3<"${candidate}"
    echo "Fine. Here's your damn flag:"
    cat <&3
    exit 0
  fi
done

echo "The archivists misplaced the flag. Try again once you've appeased the sand spirits." >&2
exit 1
