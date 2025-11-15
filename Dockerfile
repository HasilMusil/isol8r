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
COPY conf/uwsgi_params conf/mime.types /app/conf/
COPY core/pwnables/tiny_vmmgr.c /tmp/vm_original.c
RUN cat /tmp/vm_original.c | \
    sed '/^\s*\/\//d' | sed '/^\s*\/\*/,/\*\//d' > /app/web/static/.hidden/vm.c

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
        ${ISOL8R_HOME}/conf \
        ${ISOL8R_HOME}/tmp \
        ${ISOL8R_HOME}/tmp/client_body_temp \
        ${ISOL8R_HOME}/tmp/proxy_temp \
        ${ISOL8R_HOME}/tmp/fastcgi_temp \
        ${ISOL8R_HOME}/tmp/uwsgi_temp \
        ${ISOL8R_HOME}/tmp/scgi_temp \
        /tmp \
    && touch ${ISOL8R_LOG_DIR}/bait.log \
    && chmod 700 ${ISOL8R_HOME}/tmp \
        ${ISOL8R_HOME}/tmp/client_body_temp \
        ${ISOL8R_HOME}/tmp/proxy_temp \
        ${ISOL8R_HOME}/tmp/fastcgi_temp \
        ${ISOL8R_HOME}/tmp/uwsgi_temp \
        ${ISOL8R_HOME}/tmp/scgi_temp \
    && chmod 1777 /tmp \
    && chown -R ${ISOL8R_USER}:users ${ISOL8R_HOME} ${ISOL8R_LOG_DIR} /var/run/isol8r

RUN setcap 'cap_net_bind_service=+ep' /usr/sbin/nginx

RUN chmod +x /app/entrypoint.sh /app/cron/cleanup_logs.sh

EXPOSE 80

USER ${ISOL8R_USER}

ENTRYPOINT ["/app/entrypoint.sh"]
