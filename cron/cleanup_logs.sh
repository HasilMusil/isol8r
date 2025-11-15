#!/usr/bin/env bash
set -euo pipefail

LOG_FILE="${ISOL8R_BAIT_LOG:-/app/logs/bait.log}"
LOG_DIR="$(dirname "${LOG_FILE}")"
mkdir -p "${LOG_DIR}" 2>/dev/null || true

ensure_log_dir_writable() {
  local sentinel="${LOG_DIR}/.permcheck"
  if touch "${sentinel}" 2>/dev/null; then
    rm -f "${sentinel}"
    return 0
  fi
  if chown -R "$(id -u)":"$(id -g)" "${LOG_DIR}" 2>/dev/null && touch "${sentinel}" 2>/dev/null; then
    rm -f "${sentinel}"
    return 0
  fi
  rm -f "${sentinel}"
  return 1
}

if ! ensure_log_dir_writable; then
  exit 0
fi

: > "${LOG_FILE}"
{
  echo "Nice try. Bait reset."
  printf '💣 bait.log wiped @ %s
' "$(date '+%Y-%m-%d %H:%M:%S %Z')"
} >> "${LOG_FILE}"
