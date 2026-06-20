#!/bin/sh
set -eu

: "${WAF_UPSTREAM:?WAF_UPSTREAM must point to the protected application}"
: "${KRAKEN_UI_ADMIN_PASSWORD:?KRAKEN_UI_ADMIN_PASSWORD is required}"
: "${KRAKEN_UI_OPERATOR_PASSWORD:?KRAKEN_UI_OPERATOR_PASSWORD is required}"
: "${KRAKEN_UI_PASSWORD_KEY:?KRAKEN_UI_PASSWORD_KEY is required}"
: "${KRAKEN_UI_SESSION_KEY:?KRAKEN_UI_SESSION_KEY is required}"
: "${BEARER_PASSWORD:?BEARER_PASSWORD is required}"
: "${RORSCHACH_SECRET_EVEN:?RORSCHACH_SECRET_EVEN is required}"
: "${RORSCHACH_SECRET_ODD:?RORSCHACH_SECRET_ODD is required}"

shutdown() {
    kill "${WAF_PID:-0}" "${UI_PID:-0}" 2>/dev/null || true
    wait "${WAF_PID:-0}" "${UI_PID:-0}" 2>/dev/null || true
}
trap shutdown INT TERM EXIT

cd /opt/krakenwaf
/usr/local/bin/krakenwaf \
    --listen=0.0.0.0:8443 \
    --upstream="${WAF_UPSTREAM}" \
    --allow-private-upstream \
    --metrics-port=4343 \
    --rule-management-port=4342 &
WAF_PID=$!

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

    curl --silent --show-error --fail --insecure \
        --cookie "${cookie_jar}" --cookie-jar "${cookie_jar}" \
        --data-urlencode "csrf_token=${add_csrf}" \
        --data-urlencode "username=operator" \
        --data-urlencode "email=${KRAKEN_UI_OPERATOR_EMAIL:-operator@example.invalid}" \
        --data-urlencode "user_type=operator" \
        --data-urlencode "password=${KRAKEN_UI_OPERATOR_PASSWORD}" \
        https://127.0.0.1:3443/kraken_ui/auth/insert_user_action --output /dev/null
}

attempt=0
until curl --silent --fail --insecure https://127.0.0.1:3443/health >/dev/null; do
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
    sleep 2
done
echo "KrakenWAF or Kraken UI exited unexpectedly" >&2
exit 1
