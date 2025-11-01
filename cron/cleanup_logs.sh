#!/usr/bin/env bash
# cleanup_logs.sh - invoked by busybox cron every five minutes
# Purpose: reset the bait log so automated scanners cannot mine historical
# entries. The script immediately appends a sarcastic blurb so analysts know
# when the reset occurred. If the log directory vanishes, it is recreated on
# the spot because entropy is undefeated.
set -euo pipefail

LOG_FILE="${ISOL8R_BAIT_LOG:-/app/logs/bait.log}"
LOG_DIR="$(dirname "${LOG_FILE}")"
mkdir -p "${LOG_DIR}"
: > "${LOG_FILE}"
{
  echo "Nice try. Bait reset."
  printf '💣 bait.log wiped @ %s
' "$(date '+%Y-%m-%d %H:%M:%S %Z')"
} >> "${LOG_FILE}"
