#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Smoke-test the KrakenWAF + Kraken UI lab end-to-end.
#
# It builds the combined image, starts one profile (DVWA or Juice Shop), waits
# for both services to become healthy, and then probes:
#   1. Kraken UI health + login page (CSRF token present)
#   2. The WAF-protected upstream answers a benign request
#   3. The WAF blocks an obvious SQLi/XSS payload (HTTP 403)
#
# Requires: docker (with the compose plugin) and outbound access to Docker Hub.
#
# Usage:
#   ./deploy/WAF_n_WEB_UI/test-lab.sh [dvwa|juice-shop] [--keep] [--no-build]
#
#   dvwa | juice-shop   profile to run (default: dvwa)
#   --keep              leave the stack running after the tests
#   --no-build          reuse the existing image (skip --build)
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

PROFILE="dvwa"
KEEP=0
BUILD_FLAG="--build"

for arg in "$@"; do
    case "$arg" in
        dvwa|juice-shop) PROFILE="$arg" ;;
        --keep)          KEEP=1 ;;
        --no-build)      BUILD_FLAG="" ;;
        -h|--help)       sed -n '2,20p' "$0"; exit 0 ;;
        *) echo "unknown argument: $arg" >&2; exit 2 ;;
    esac
done

# Resolve the repo root from this script's location (…/deploy/WAF_n_WEB_UI).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
cd "${REPO_ROOT}"

COMPOSE_FILE="deploy/WAF_n_WEB_UI/compose.${PROFILE}.yaml"
[ -f "${COMPOSE_FILE}" ] || { echo "compose file not found: ${COMPOSE_FILE}" >&2; exit 1; }

# DVWA publishes the protected app on 8443; Juice Shop on 9443. UI is 3443 in both.
if [ "${PROFILE}" = "juice-shop" ]; then APP_PORT=9443; else APP_PORT=8443; fi
UI_PORT=3443

# Pick the compose CLI (v2 plugin preferred, v1 fallback).
if docker compose version >/dev/null 2>&1; then COMPOSE=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then COMPOSE=(docker-compose)
else echo "docker compose is required" >&2; exit 1; fi

green() { printf '\033[32m%s\033[0m\n' "$*"; }
red()   { printf '\033[31m%s\033[0m\n' "$*"; }
info()  { printf '\033[36m▶ %s\033[0m\n' "$*"; }

FAILURES=0
check() { # check <description> <expected> <actual>
    if [ "$2" = "$3" ]; then green "  PASS: $1 (got $3)"; else
        red "  FAIL: $1 (expected $2, got $3)"; FAILURES=$((FAILURES + 1)); fi
}

cleanup() {
    if [ "${KEEP}" -eq 1 ]; then
        info "Leaving the stack running (--keep). Stop it with:"
        echo "  ${COMPOSE[*]} -f ${COMPOSE_FILE} down -v"
    else
        info "Tearing down the stack…"
        "${COMPOSE[@]}" -f "${COMPOSE_FILE}" down -v >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

# curl helper: -k because the lab uses a self-signed cert; print the HTTP status.
status() { curl -k -s -o /dev/null -w '%{http_code}' --max-time 10 "$@" 2>/dev/null || echo "000"; }
body()   { curl -k -s --max-time 10 "$@" 2>/dev/null || true; }

wait_for() { # wait_for <url> <timeout_secs>
    local url="$1" timeout="${2:-180}" waited=0
    until [ "$(status "$url")" != "000" ]; do
        waited=$((waited + 2))
        [ "$waited" -ge "$timeout" ] && return 1
        sleep 2
    done
}

info "Profile: ${PROFILE}  |  protected app: https://localhost:${APP_PORT}  |  UI: https://localhost:${UI_PORT}"
info "Building and starting the stack (first build compiles Rust — be patient)…"
# shellcheck disable=SC2086
"${COMPOSE[@]}" -f "${COMPOSE_FILE}" up ${BUILD_FLAG} -d

info "Waiting for Kraken UI health endpoint…"
if ! wait_for "https://localhost:${UI_PORT}/health" 300; then
    red "Kraken UI never became reachable. Recent logs:"
    "${COMPOSE[@]}" -f "${COMPOSE_FILE}" logs --tail=40 || true
    exit 1
fi

info "Waiting for the WAF-protected endpoint…"
wait_for "https://localhost:${APP_PORT}/" 120 || true

echo
info "Running checks"

# 1. UI health.
check "Kraken UI /health" "200" "$(status "https://localhost:${UI_PORT}/health")"

# 2. UI login page reachable and CSRF-protected.
LOGIN_HTML="$(body "https://localhost:${UI_PORT}/kraken_ui/login")"
check "Kraken UI login page" "200" "$(status "https://localhost:${UI_PORT}/kraken_ui/login")"
if printf '%s' "${LOGIN_HTML}" | grep -q 'name="csrf_token"'; then
    green "  PASS: login page carries a csrf_token"
else
    red "  FAIL: login page has no csrf_token"; FAILURES=$((FAILURES + 1))
fi

# 3. Benign request through the WAF reaches the upstream (any non-5xx/403 is fine).
APP_BENIGN="$(status "https://localhost:${APP_PORT}/")"
if [ "${APP_BENIGN}" != "000" ] && [ "${APP_BENIGN}" != "403" ] && [ "${APP_BENIGN:0:1}" != "5" ]; then
    green "  PASS: benign request through the WAF (got ${APP_BENIGN})"
else
    red "  FAIL: benign request through the WAF (got ${APP_BENIGN})"; FAILURES=$((FAILURES + 1))
fi

# 4. The WAF blocks an obvious attack payload with HTTP 403.
SQLI="$(status "https://localhost:${APP_PORT}/?id=1%27%20OR%20%271%27%3D%271%27--")"
check "WAF blocks SQLi payload" "403" "${SQLI}"
XSS="$(status "https://localhost:${APP_PORT}/?q=%3Cscript%3Ealert(1)%3C/script%3E")"
check "WAF blocks XSS payload" "403" "${XSS}"

echo
echo "Test accounts (lab only):"
echo "  admin    / Tentacle-Root!2026"
echo "  operator / DeepCurrent!2026"
echo "  UI: https://localhost:${UI_PORT}/kraken_ui/login"
echo

if [ "${FAILURES}" -eq 0 ]; then
    green "ALL CHECKS PASSED ✓"
    exit 0
else
    red "${FAILURES} CHECK(S) FAILED ✗  — recent logs:"
    "${COMPOSE[@]}" -f "${COMPOSE_FILE}" logs --tail=30 || true
    exit 1
fi
