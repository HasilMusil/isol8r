FROM python:3.11-slim

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    ISOL8R_HOME=/app \
    UWSGI_INI=/app/conf/uwsgi.ini \
    NGINX_CONF=/app/conf/nginx.conf \
    ISOL8R_LOG_DIR=/app/logs \
    ISOL8R_USER=ctfuser

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        nginx \
        uwsgi \
        uwsgi-plugin-python3 \
        build-essential \
        python3-dev \
        gcc \
        busybox \
        cron \
        logrotate \
        libcap2-bin \
        git \
        curl \
        procps \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN getent group users >/dev/null || groupadd --gid 100 users
RUN id -u ${ISOL8R_USER} &>/dev/null || useradd --create-home --gid users --uid 1001 --shell /bin/bash ${ISOL8R_USER}

WORKDIR ${ISOL8R_HOME}

COPY . ${ISOL8R_HOME}

RUN pip install --no-cache-dir \
        flask==3.0.2 \
        werkzeug==3.0.1 \
        uwsgi==2.0.24

RUN gcc \
        core/jail_binaries/sandboxed_echo.c \
        -o core/jail_binaries/sandboxed_echo \
        -DLOG_PATH=\"${ISOL8R_HOME}/logs/bait.log\" \
        -static-pie \
        -O2 \
        -fstack-protector-strong \
        -Wall \
        -Wextra \
        -Wpedantic \
    && chown ${ISOL8R_USER}:users core/jail_binaries/sandboxed_echo

RUN gcc \
        core/pwnables/tiny_vmmgr.c \
        -o core/pwnables/tiny_vmmgr \
        -Wall \
        -Wextra \
        -O2 \
        -fno-stack-protector \
        -z execstack \
    && chown ${ISOL8R_USER}:users core/pwnables/tiny_vmmgr \
    && chmod 750 core/pwnables/tiny_vmmgr

RUN mkdir -p ${ISOL8R_LOG_DIR} /var/run/isol8r /var/cache/nginx \
    && touch ${ISOL8R_LOG_DIR}/bait.log \
    && chown -R ${ISOL8R_USER}:users ${ISOL8R_HOME} ${ISOL8R_LOG_DIR} /var/run/isol8r

RUN setcap 'cap_net_bind_service=+ep' /usr/sbin/nginx

RUN chmod +x /app/entrypoint.sh /app/cron/cleanup_logs.sh \
    && find /app/core/shell_traps/troll_binaries -type f -exec chmod +x {} +

RUN cat <<'EOF' > /etc/profile.d/isol8r_traps.sh
# Source ISOL8R shell traps for interactive shells
if [ -f /app/core/shell_traps/aliases.sh ]; then
    . /app/core/shell_traps/aliases.sh
fi
EOF

RUN chmod 644 /etc/profile.d/isol8r_traps.sh \
    && touch /home/${ISOL8R_USER}/.bashrc \
    && chown ${ISOL8R_USER}:users /home/${ISOL8R_USER}/.bashrc \
    && (grep -qxF '. /app/core/shell_traps/aliases.sh' /home/${ISOL8R_USER}/.bashrc || echo '. /app/core/shell_traps/aliases.sh' >> /home/${ISOL8R_USER}/.bashrc)

EXPOSE 80

USER ${ISOL8R_USER}

ENTRYPOINT ["/app/entrypoint.sh"]
