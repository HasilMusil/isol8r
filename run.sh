#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="${PROJECT_ROOT}/logs/bait.log"
mkdir -p "${PROJECT_ROOT}/logs"
touch "${LOG_FILE}"

TIMESTAMP() { date "+%Y-%m-%d %H:%M:%S %Z"; }

log() {
    local message="$*"
    printf "[%s] %s\n" "$(TIMESTAMP)" "${message}" | tee -a "${LOG_FILE}"
}

abort() {
    local message="$1"
    log "❌ ERROR: ${message}"
    exit 1
}

trap 'abort "run.sh aborted at line ${LINENO}."' ERR

if [[ ${ISOL8R_RUN_AS_ROOT:-0} -ne 1 && "$(id -u)" -ne 0 ]]; then
    if command -v sudo >/dev/null 2>&1; then
        log "Elevating privileges with sudo."
        exec sudo ISOL8R_RUN_AS_ROOT=1 bash "$0" "$@"
    else
        abort "Root privileges required. Install sudo or rerun as root."
    fi
fi

INSTALL_SERVICE=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --install-service)
            INSTALL_SERVICE=1
            shift
            ;;
        --help|-h)
            cat <<'EOF'
ISOL8R run.sh usage:
  ./run.sh [--install-service]

  --install-service   Generate and enable a systemd service to keep the ISOL8R
                      challenge running across reboots.
EOF
            exit 0
            ;;
        *)
            abort "Unknown argument: $1"
            ;;
    esac
done

cat <<'BANNER'
================================================================================
🌐  ISOL8R :: Project Sandtrap - Automated Lab Deployment
================================================================================
This script will verify dependencies, configure permissions, build containers,
and launch the full CTF environment without manual intervention.
BANNER

log "Starting ISOL8R deployment from ${PROJECT_ROOT}"

detect_pkg_manager() {
    for candidate in apt-get dnf yum pacman zypper apk; do
        if command -v "${candidate}" >/dev/null 2>&1; then
            echo "${candidate}"
            return 0
        fi
    done
    return 1
}

PKG_MANAGER="$(detect_pkg_manager)" || abort "Unsupported distribution: no known package manager detected."
log "Detected package manager: ${PKG_MANAGER}"

ensure_packages() {
    local packages=("$@")
    case "${PKG_MANAGER}" in
        apt-get)
            apt-get update -y
            DEBIAN_FRONTEND=noninteractive apt-get install -y "${packages[@]}"
            ;;
        dnf)
            dnf install -y "${packages[@]}"
            ;;
        yum)
            yum install -y "${packages[@]}"
            ;;
        pacman)
            pacman -Syu --noconfirm "${packages[@]}"
            ;;
        zypper)
            zypper --non-interactive install "${packages[@]}"
            ;;
        apk)
            apk add --no-cache "${packages[@]}"
            ;;
        *)
            abort "Package installation not implemented for ${PKG_MANAGER}"
            ;;
    esac
}

ensure_docker() {
    if command -v docker >/dev/null 2>&1; then
        log "Docker already installed: $(docker --version)"
        return
    fi

    log "Docker missing. Installing docker engine."
    case "${PKG_MANAGER}" in
        apt-get)
            ensure_packages ca-certificates curl gnupg lsb-release
            install -m 0755 -d /etc/apt/keyrings
            if [[ ! -f /etc/apt/keyrings/docker.gpg ]]; then
                curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
                chmod a+r /etc/apt/keyrings/docker.gpg
                . /etc/os-release
                echo \
"deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/${ID} \
$(lsb_release -cs) stable" >/etc/apt/sources.list.d/docker.list
            fi
            apt-get update -y
            DEBIAN_FRONTEND=noninteractive apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
            ;;
        dnf)
            ensure_packages dnf-plugins-core
            dnf config-manager --add-repo https://download.docker.com/linux/fedora/docker-ce.repo
            dnf install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
            ;;
        yum)
            ensure_packages yum-utils
            yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
            yum install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
            ;;
        pacman)
            ensure_packages docker docker-compose
            ;;
        zypper)
            ensure_packages docker docker-compose
            ;;
        apk)
            ensure_packages docker docker-cli-compose
            ;;
        *)
            abort "Automatic Docker installation unsupported on ${PKG_MANAGER}."
            ;;
    esac
}

ensure_docker_compose() {
    if docker compose version >/dev/null 2>&1; then
        COMPOSE_CMD=(docker compose)
        log "Docker Compose plugin available."
        return
    fi

    if command -v docker-compose >/dev/null 2>&1; then
        COMPOSE_CMD=(docker-compose)
        log "Legacy docker-compose binary detected."
        return
    fi

    log "Docker Compose not found. Installing docker-compose plugin/binary."
    case "${PKG_MANAGER}" in
        apt-get)
            DEBIAN_FRONTEND=noninteractive apt-get install -y docker-compose-plugin
            ;;
        dnf|yum)
            ensure_packages docker-compose-plugin
            ;;
        pacman)
            ensure_packages docker-compose
            ;;
        zypper)
            ensure_packages docker-compose
            ;;
        apk)
            ensure_packages docker-cli-compose
            ;;
        *)
            abort "Failed to install Docker Compose on ${PKG_MANAGER}"
            ;;
    esac

    if docker compose version >/dev/null 2>&1; then
        COMPOSE_CMD=(docker compose)
    elif command -v docker-compose >/dev/null 2>&1; then
        COMPOSE_CMD=(docker-compose)
    else
        abort "Docker Compose installation unsuccessful."
    fi
}

ensure_docker

if command -v systemctl >/dev/null 2>&1; then
    if ! systemctl is-active --quiet docker; then
        log "Starting docker service."
        systemctl enable --now docker
    fi
elif command -v service >/dev/null 2>&1; then
    service docker start || true
fi

ensure_docker_compose
log "Compose command resolved to: ${COMPOSE_CMD[*]}"

check_port_free() {
    local port="$1"
    if command -v ss >/dev/null 2>&1; then
        if ss -ltn "sport = :${port}" | tail -n +2 | grep -q .; then
            abort "Port ${port} is already in use."
        fi
    elif command -v lsof >/dev/null 2>&1; then
        if lsof -iTCP:"${port}" -sTCP:LISTEN >/dev/null 2>&1; then
            abort "Port ${port} is already in use."
        fi
    else
        log "Warning: Unable to verify port ${port} availability (ss/lsof unavailable)."
    fi
    log "Port ${port} available."
}

check_port_free 80
check_port_free 8080

log "Ensuring directory structure and permissions."
install -d -m 0755 "${PROJECT_ROOT}/logs" "${PROJECT_ROOT}/data/fake_flags"

log "Aligning host logs directory ownership with container user (1001:100)."
if ! chown -R 1001:100 "${PROJECT_ROOT}/logs"; then
    abort "Failed to chown ${PROJECT_ROOT}/logs to 1001:100. Adjust permissions and rerun."
fi
chmod -R u+rwX,g+rwX "${PROJECT_ROOT}/logs"

find "${PROJECT_ROOT}" -type f -name "*.sh" -exec chmod +x {} +
find "${PROJECT_ROOT}" -type f -name "*.py" -exec chmod +x {} +
find "${PROJECT_ROOT}" -type f -name "*.c" -exec chmod 0644 {} +

if [[ -f "${PROJECT_ROOT}/src/core/pwnables/tiny_vmmgr" ]]; then
    chmod 0750 "${PROJECT_ROOT}/src/core/pwnables/tiny_vmmgr"
fi

if [[ -f "${PROJECT_ROOT}/src/core/jail_binaries/sandboxed_echo" ]]; then
    chmod 0750 "${PROJECT_ROOT}/src/core/jail_binaries/sandboxed_echo"
fi

if ! getent group ctf >/dev/null 2>&1; then
    groupadd --system ctf
    log "Created system group 'ctf'."
fi

if [[ -f "${PROJECT_ROOT}/data/real_flag.txt" ]]; then
    chown root:ctf "${PROJECT_ROOT}/data/real_flag.txt"
    chmod 0640 "${PROJECT_ROOT}/data/real_flag.txt"
    log "Set ownership on data/real_flag.txt to root:ctf with 0640 permissions."
fi



log "Validating cron script permissions."
chmod +x "${PROJECT_ROOT}/cron/cleanup_logs.sh"

compose() {
    "${COMPOSE_CMD[@]}" "$@"
}

log "Building Docker images."
compose -f "${PROJECT_ROOT}/docker-compose.yml" build

log "Launching ISOL8R stack."
compose -f "${PROJECT_ROOT}/docker-compose.yml" up -d

log "Running cron cleanup once inside container."
compose -f "${PROJECT_ROOT}/docker-compose.yml" exec -T isol8r /app/cron/cleanup_logs.sh || log "Cron pre-run skipped (container may still be starting)."

if [[ ${INSTALL_SERVICE} -eq 1 ]]; then
    if command -v systemctl >/dev/null 2>&1; then
        SERVICE_PATH="/etc/systemd/system/isol8r.service"
        DOCKER_BIN="$(command -v docker)"
        if [[ "${COMPOSE_CMD[0]}" == "docker" ]]; then
            SERVICE_EXEC="${DOCKER_BIN} compose"
        else
            SERVICE_EXEC="$(command -v docker-compose)"
        fi
        cat >"${SERVICE_PATH}" <<EOF
[Unit]
Description=ISOL8R Project Sandtrap
After=network-online.target docker.service
Wants=network-online.target docker.service

[Service]
Type=oneshot
WorkingDirectory=${PROJECT_ROOT}
RemainAfterExit=yes
ExecStart=${SERVICE_EXEC} -f ${PROJECT_ROOT}/docker-compose.yml up -d
ExecStop=${SERVICE_EXEC} -f ${PROJECT_ROOT}/docker-compose.yml down
TimeoutStartSec=180

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable --now isol8r.service
        log "Systemd service isol8r.service installed and started."
    else
        log "systemctl not available; skipping service installation."
    fi
fi

compose -f "${PROJECT_ROOT}/docker-compose.yml" ps

log "Deployment complete."
echo "ISOL8R Challenge Deployed Successfully."
