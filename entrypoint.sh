#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# ISOL8R Entrypoint
#   Responsibilities:
#     - ensure bait log existence
#     - launch a user-scoped cron daemon via busybox
#     - start uWSGI with the Flask application
#     - front the stack with nginx running in the foreground
#     - export a sarcastic banner so operators know pain has begun
# ---------------------------------------------------------------------------
set -euo pipefail

BASE_DIR="/app"
LOG_DIR="${BASE_DIR}/logs"
ENTRYPOINT_TRACE="${LOG_DIR}/entrypoint.trace"
BAIT_LOG="${LOG_DIR}/bait.log"
CRON_LOG="${LOG_DIR}/cron.log"
CRON_SPOOL_ROOT="${BASE_DIR}/cron/spool"
CRON_FILE="${CRON_SPOOL_ROOT}/ctfuser"
UWSGI_SOCKET="/tmp/uwsgi.sock"
UWSGI_INI_PATH="${UWSGI_INI:-/app/conf/uwsgi.ini}"
NGINX_CONF_PATH="${NGINX_CONF:-/app/conf/nginx.conf}"

mkdir -p "${LOG_DIR}" "${CRON_SPOOL_ROOT}"
: >"${ENTRYPOINT_TRACE}"

log_boot_step() {
  local message=$1
  printf '[TRACE] [BOOT] Step: %s\n' "${message}" >> "${ENTRYPOINT_TRACE}"
}

log_boot_step "Sandtrap entrypoint initializing"
log_boot_step "Ensured log directory at ${LOG_DIR} and cron spool at ${CRON_SPOOL_ROOT}"

if [[ ! -f "${BAIT_LOG}" ]]; then
  touch "${BAIT_LOG}"
  log_boot_step "Created bait log at ${BAIT_LOG}"
else
  log_boot_step "Detected existing bait log at ${BAIT_LOG}"
fi

log_boot_step "Entrypoint started at $(date '+%Y-%m-%d %H:%M:%S %Z')"
log_boot_step "Applying restrictive umask 077"
umask 077

log_boot_step "Writing cron schedule for ctfuser"
cat <<'EOF' > "${CRON_FILE}.tmp"
*/5 * * * * /app/cron/cleanup_logs.sh >> /app/logs/cron.log 2>&1
EOF
mv "${CRON_FILE}.tmp" "${CRON_FILE}"
chmod 600 "${CRON_FILE}"
log_boot_step "Cron file deployed to ${CRON_FILE} with permissions 600"

busybox crond -f -c "${CRON_SPOOL_ROOT}" -L "${CRON_LOG}" &
CRON_PID=$!
log_boot_step "busybox crond started with pid ${CRON_PID}"

declare -a PROCS
PROCS+=("${CRON_PID}")

rm -f "${UWSGI_SOCKET}"
log_boot_step "Removed stale uWSGI socket at ${UWSGI_SOCKET}"
uwsgi --ini "${UWSGI_INI_PATH}" --die-on-term &
UWSGI_PID=$!
PROCS+=("${UWSGI_PID}")
log_boot_step "uWSGI spawned from ${UWSGI_INI_PATH} with pid ${UWSGI_PID}"

for attempt in {1..30}; do
  if [[ -S "${UWSGI_SOCKET}" ]]; then
    log_boot_step "uWSGI socket available at ${UWSGI_SOCKET}"
    break
  fi
  sleep 0.5
  if [[ ${attempt} -eq 30 ]]; then
    log_boot_step "uWSGI socket missing after ${attempt} attempts; aborting"
    exit 1
  fi
done

cleanup() {
  local code=$?
  log_boot_step "Cleanup handler engaged; terminating managed processes"
  for pid in "${PROCS[@]}"; do
    if kill -0 "${pid}" 2>/dev/null; then
      kill "${pid}" 2>/dev/null || true
    fi
  done
  wait || true
  log_boot_step "Entrypoint exiting with status ${code}"
}
trap cleanup EXIT INT TERM

log_boot_step "Starting nginx with config ${NGINX_CONF_PATH} in foreground"
nginx -c "${NGINX_CONF_PATH}" -g 'daemon off;'
