#!/bin/sh
set -eu

: "${WAF_UPSTREAM:?WAF_UPSTREAM must point to the protected application}"
: "${KRAKEN_UI_ADMIN_PASSWORD:?KRAKEN_UI_ADMIN_PASSWORD is required}"
: "${KRAKEN_UI_OPERATOR_PASSWORD:?KRAKEN_UI_OPERATOR_PASSWORD is required}"
: "${KRAKEN_UI_AUDITOR_PASSWORD:?KRAKEN_UI_AUDITOR_PASSWORD is required}"
: "${KRAKEN_UI_PASSWORD_KEY:?KRAKEN_UI_PASSWORD_KEY is required}"
: "${KRAKEN_UI_SESSION_KEY:?KRAKEN_UI_SESSION_KEY is required}"
: "${BEARER_PASSWORD:?BEARER_PASSWORD is required}"
: "${RORSCHACH_SECRET_EVEN:?RORSCHACH_SECRET_EVEN is required}"
: "${RORSCHACH_SECRET_ODD:?RORSCHACH_SECRET_ODD is required}"

shutdown() {
    kill "${REDIS_PID:-0}" "${WAF_PID:-0}" "${UI_PID:-0}" 2>/dev/null || true
    wait "${REDIS_PID:-0}" "${WAF_PID:-0}" "${UI_PID:-0}" 2>/dev/null || true
}
trap shutdown INT TERM EXIT

REDIS_SECRET_DIR=/run/secrets/krakenwaf
REDIS_TLS_DIR=/opt/redis/tls
REDIS_CONF_DIR=/opt/redis/conf
REDIS_DATA_DIR=/opt/redis/data
REDIS_HOST=localhost
REDIS_PORT=6380
REDIS_USERNAME_FILE="${REDIS_SECRET_DIR}/REDIS_USERNAME"
REDIS_PASSWORD_FILE="${REDIS_SECRET_DIR}/REDIS_PASSWORD"
REDIS_ACL_FILE="${REDIS_CONF_DIR}/users.acl"
REDIS_CONF_FILE="${REDIS_CONF_DIR}/redis.conf"
REDIS_SERVER_BIN="${REDIS_SERVER_BIN:-$(command -v redis-server)}"
REDIS_CLI_BIN="${REDIS_CLI_BIN:-$(command -v redis-cli)}"

ensure_redis_secrets() {
    umask 077
    mkdir -p "${REDIS_SECRET_DIR}"
    if [ ! -s "${REDIS_USERNAME_FILE}" ]; then
        printf '%s\n' "kraken-rate-limit" > "${REDIS_USERNAME_FILE}"
    fi
    if [ ! -s "${REDIS_PASSWORD_FILE}" ]; then
        openssl rand -base64 48 | tr -d '\n' > "${REDIS_PASSWORD_FILE}"
        printf '\n' >> "${REDIS_PASSWORD_FILE}"
    fi
}

ensure_redis_tls() {
    if [ -s "${REDIS_TLS_DIR}/ca.crt" ] && [ -s "${REDIS_TLS_DIR}/server.crt" ] && [ -s "${REDIS_TLS_DIR}/server.key" ]; then
        return 0
    fi

    mkdir -p "${REDIS_TLS_DIR}"
    openssl genrsa -out "${REDIS_TLS_DIR}/ca.key" 4096 >/dev/null 2>&1
    openssl req -x509 -new -nodes -key "${REDIS_TLS_DIR}/ca.key" \
        -sha256 -days 365 -out "${REDIS_TLS_DIR}/ca.crt" \
        -subj "/CN=krakenwaf-local-redis-ca" >/dev/null 2>&1

    openssl genrsa -out "${REDIS_TLS_DIR}/server.key" 4096 >/dev/null 2>&1
    openssl req -new -key "${REDIS_TLS_DIR}/server.key" \
        -out "${REDIS_TLS_DIR}/server.csr" \
        -subj "/CN=${REDIS_HOST}" >/dev/null 2>&1
    tmp_ext="$(mktemp)"
    printf '%s\n' "subjectAltName=DNS:${REDIS_HOST},IP:127.0.0.1" > "${tmp_ext}"
    openssl x509 -req -in "${REDIS_TLS_DIR}/server.csr" \
        -CA "${REDIS_TLS_DIR}/ca.crt" \
        -CAkey "${REDIS_TLS_DIR}/ca.key" \
        -CAcreateserial \
        -out "${REDIS_TLS_DIR}/server.crt" \
        -days 365 -sha256 -extfile "${tmp_ext}" >/dev/null 2>&1
    rm -f "${tmp_ext}" "${REDIS_TLS_DIR}/server.csr" "${REDIS_TLS_DIR}/ca.srl"
    chmod 600 "${REDIS_TLS_DIR}/ca.key" "${REDIS_TLS_DIR}/server.key"
}

write_redis_acl() {
    redis_user="$(tr -d '\n' < "${REDIS_USERNAME_FILE}")"
    redis_password="$(tr -d '\n' < "${REDIS_PASSWORD_FILE}")"
    printf '%s\n' \
        "user default off" \
        "user ${redis_user} on >${redis_password} resetkeys ~krakenwaf:rl:* ~krakenwaf:ban:* ~kraken-ui:ratelimit:* resetchannels -@all +@connection +eval +evalsha +script|load +expire +get +hget +hset +set +time" \
        > "${REDIS_ACL_FILE}"
}

write_redis_conf() {
    cat > "${REDIS_CONF_FILE}" <<EOF
bind 127.0.0.1 ::1
protected-mode yes
port 0
tls-port ${REDIS_PORT}
tls-cert-file ${REDIS_TLS_DIR}/server.crt
tls-key-file ${REDIS_TLS_DIR}/server.key
tls-ca-cert-file ${REDIS_TLS_DIR}/ca.crt
tls-auth-clients no
tls-protocols "TLSv1.2 TLSv1.3"
daemonize no
dir ${REDIS_DATA_DIR}
dbfilename dump.rdb
save ""
appendonly no
aclfile ${REDIS_ACL_FILE}
logfile ""
rename-command ACL ""
rename-command CONFIG ""
rename-command DEBUG ""
rename-command FLUSHALL ""
rename-command FLUSHDB ""
rename-command KEYS ""
rename-command MODULE ""
rename-command MONITOR ""
rename-command REPLICAOF ""
rename-command SAVE ""
rename-command SHUTDOWN ""
EOF
}

start_redis() {
    "${REDIS_SERVER_BIN}" "${REDIS_CONF_FILE}" &
    REDIS_PID=$!
}

wait_for_redis() {
    redis_user="$(tr -d '\n' < "${REDIS_USERNAME_FILE}")"
    redis_password="$(tr -d '\n' < "${REDIS_PASSWORD_FILE}")"
    attempt=0
    until "${REDIS_CLI_BIN}" \
        --tls \
        --cacert "${REDIS_TLS_DIR}/ca.crt" \
        --user "${redis_user}" \
        --pass "${redis_password}" \
        -h "${REDIS_HOST}" \
        -p "${REDIS_PORT}" \
        ping >/dev/null 2>&1; do
        attempt=$((attempt + 1))
        if [ "${attempt}" -ge 30 ]; then
            echo "Embedded Redis did not become healthy" >&2
            exit 1
        fi
        sleep 1
    done
}

sync_ui_security_headers() {
    ui_headers=/opt/kraken-ui/conf/headers_sec.txt
    policy_path=$(sed -n \
        's/^[[:space:]]*header-protection-injection[[:space:]]*:[[:space:]]*//p' \
        /opt/krakenwaf/conf/proxy.yaml \
        | head -n 1 \
        | sed 's/[[:space:]]#.*$//;s/^[[:space:]]*//;s/[[:space:]]*$//')

    case "${policy_path}" in
        \"*\") policy_path="${policy_path#\"}"; policy_path="${policy_path%\"}" ;;
        \'*\') policy_path="${policy_path#\'}"; policy_path="${policy_path%\'}" ;;
    esac

    mkdir -p /opt/kraken-ui/conf
    : > "${ui_headers}"

    if [ -z "${policy_path}" ]; then
        return 0
    fi

    case "${policy_path}" in
        ./*) resolved_path="/opt/krakenwaf/${policy_path#./}" ;;
        /*)  resolved_path="${policy_path}" ;;
        *)   resolved_path="/opt/krakenwaf/${policy_path}" ;;
    esac

    cp "${resolved_path}" "${ui_headers}"
}

wait_for_waf_alert_database() {
    db_path=/opt/krakenwaf/logs/db/vulns_alert.db
    attempt=0
    until [ -s "${db_path}" ]; do
        if ! kill -0 "${WAF_PID}" 2>/dev/null; then
            echo "KrakenWAF exited before creating ${db_path}" >&2
            wait "${WAF_PID}" 2>/dev/null || true
            exit 1
        fi
        attempt=$((attempt + 1))
        if [ "${attempt}" -ge 60 ]; then
            echo "KrakenWAF did not create ${db_path}" >&2
            exit 1
        fi
        sleep 1
    done
}

ensure_redis_secrets
ensure_redis_tls
write_redis_acl
write_redis_conf
start_redis
wait_for_redis

export REDIS_USERNAME_FILE
export REDIS_PASSWORD_FILE

# The WAF starts with no CLI flags: it auto-loads conf/proxy.yaml (plus
# ratelimit.yaml / websocket.yaml) from the working directory. The only value
# that varies per profile is the protected upstream, so we write it into
# conf/proxy.yaml before launch. Everything else (listen 0.0.0.0:8443,
# metrics-port 4343, rule_management_port 4342, allow-private-upstream, sni-map,
# block page) already ships in conf/proxy.yaml.
sed -i \
    -e "s|^[[:space:]]*upstream[[:space:]]*:.*|upstream : ${WAF_UPSTREAM}|" \
    /opt/krakenwaf/conf/proxy.yaml
sync_ui_security_headers

cd /opt/krakenwaf
/usr/local/bin/krakenwaf &
WAF_PID=$!
wait_for_waf_alert_database

cd /opt/kraken-ui
/usr/local/bin/kraken-ui &
UI_PID=$!

bootstrap_operator() {
    cookie_jar=/tmp/kraken-ui-bootstrap.cookies
    login_page=/tmp/kraken-ui-login.html
    add_page=/tmp/kraken-ui-add-user.html

    curl --silent --show-error --fail --insecure \
        --cookie-jar "${cookie_jar}" https://127.0.0.1:3443/kraken_ui/login \
        --output "${login_page}"
    login_csrf=$(sed -n 's/.*name="csrf_token" value="\([^"]*\)".*/\1/p' "${login_page}" | head -n 1)
    test -n "${login_csrf}"

    curl --silent --show-error --fail --insecure \
        --cookie "${cookie_jar}" --cookie-jar "${cookie_jar}" \
        --data-urlencode "csrf_token=${login_csrf}" \
        --data-urlencode "login=admin" \
        --data-urlencode "password=${KRAKEN_UI_ADMIN_PASSWORD}" \
        https://127.0.0.1:3443/kraken_ui/login --output /dev/null

    curl --silent --show-error --fail --insecure \
        --cookie "${cookie_jar}" --cookie-jar "${cookie_jar}" \
        https://127.0.0.1:3443/kraken_ui/auth/insert_user \
        --output "${add_page}"
    add_csrf=$(sed -n 's/.*name="csrf_token" value="\([^"]*\)".*/\1/p' "${add_page}" | head -n 1)
    test -n "${add_csrf}"

    add_user() {
        username="$1"
        email="$2"
        user_type="$3"
        password="$4"
        curl --silent --show-error --fail --insecure \
            --cookie "${cookie_jar}" --cookie-jar "${cookie_jar}" \
            --data-urlencode "csrf_token=${add_csrf}" \
            --data-urlencode "username=${username}" \
            --data-urlencode "email=${email}" \
            --data-urlencode "user_type=${user_type}" \
            --data-urlencode "password=${password}" \
            https://127.0.0.1:3443/kraken_ui/auth/insert_user_action --output /dev/null
    }

    add_user \
        "operator" \
        "${KRAKEN_UI_OPERATOR_EMAIL:-operator@example.invalid}" \
        "operator" \
        "${KRAKEN_UI_OPERATOR_PASSWORD}"

    curl --silent --show-error --fail --insecure \
        --cookie "${cookie_jar}" --cookie-jar "${cookie_jar}" \
        https://127.0.0.1:3443/kraken_ui/auth/insert_user \
        --output "${add_page}"
    add_csrf=$(sed -n 's/.*name="csrf_token" value="\([^"]*\)".*/\1/p' "${add_page}" | head -n 1)
    test -n "${add_csrf}"

    add_user \
        "auditor" \
        "${KRAKEN_UI_AUDITOR_EMAIL:-auditor@example.invalid}" \
        "auditor" \
        "${KRAKEN_UI_AUDITOR_PASSWORD}"
}

attempt=0
until curl --silent --fail --insecure https://127.0.0.1:3443/health >/dev/null; do
    if ! kill -0 "${UI_PID}" 2>/dev/null; then
        echo "Kraken UI exited during startup" >&2
        wait "${UI_PID}" 2>/dev/null || true
        exit 1
    fi
    if ! kill -0 "${WAF_PID}" 2>/dev/null; then
        echo "KrakenWAF exited during startup" >&2
        wait "${WAF_PID}" 2>/dev/null || true
        exit 1
    fi
    attempt=$((attempt + 1))
    if [ "${attempt}" -ge 60 ]; then
        echo "Kraken UI did not become healthy" >&2
        exit 1
    fi
    sleep 1
done

if ! bootstrap_operator; then
    echo "Operator bootstrap was not completed; inspect Kraken UI logs" >&2
fi

while kill -0 "${WAF_PID}" 2>/dev/null && kill -0 "${UI_PID}" 2>/dev/null; do
    kill -0 "${REDIS_PID}" 2>/dev/null || break
    sleep 2
done
echo "Redis, KrakenWAF, or Kraken UI exited unexpectedly" >&2
exit 1
