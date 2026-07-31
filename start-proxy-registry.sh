#!/bin/bash
# Start one Proxy Registry instance. Multiple systemd units use distinct
# LISTEN_ADDR, CONTROL_LISTEN_ADDR and LOG_DIR values while sharing SQLite.

set -u

SCRIPT_PATH="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR" || exit 1

LOG_DIR="${PPAASS_PROXY_REGISTRY_LOG_DIR:-logs}"
PID_FILE="$LOG_DIR/proxy-registry.pid"
RUNTIME_ENV_FILE="${PPAASS_PROXY_REGISTRY_RUNTIME_ENV_FILE:-proxy-registry.env}"
SECRET_DIR="${PPAASS_PROXY_REGISTRY_SECRET_DIR:-.secrets}"
KEY_SECRET_FILE="$SECRET_DIR/proxy-registry-key-encryption-secret"
ADMIN_PASSWORD_FILE="$SECRET_DIR/proxy-registry-admin-password"
CONTROL_TOKEN_FILE="$SECRET_DIR/proxy-registry-control-token"
START_TIMEOUT="${PROXY_REGISTRY_START_TIMEOUT:-20}"

read_pid() {
    if [ -f "$PID_FILE" ]; then
        tr -d '[:space:]' < "$PID_FILE"
    fi
}

is_running() {
    local pid="${1:-}"
    [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null
}

load_runtime_environment() {
    if [ -f "$RUNTIME_ENV_FILE" ]; then
        set -a
        # shellcheck disable=SC1090
        . "$RUNTIME_ENV_FILE"
        set +a
    fi
    SECRET_DIR="${PPAASS_PROXY_REGISTRY_SECRET_DIR:-.secrets}"
    KEY_SECRET_FILE="$SECRET_DIR/proxy-registry-key-encryption-secret"
    ADMIN_PASSWORD_FILE="$SECRET_DIR/proxy-registry-admin-password"
    CONTROL_TOKEN_FILE="$SECRET_DIR/proxy-registry-control-token"
}

read_required_secret() {
    local path="$1"
    local label="$2"
    local value

    if [ ! -r "$path" ] || [ -L "$path" ] || [ ! -f "$path" ]; then
        echo "Error: $label file is missing, unreadable, or unsafe: $path" >&2
        return 1
    fi
    value="$(cat "$path")"
    if [ "${#value}" -lt 32 ] || [ "${#value}" -gt 512 ]; then
        echo "Error: $label must contain 32..=512 bytes." >&2
        return 1
    fi
    case "$value" in
        *[[:space:]]*)
            echo "Error: $label must not contain whitespace." >&2
            return 1
            ;;
    esac
    printf '%s' "$value"
}

load_secret_environment() {
    local encryption_secret control_token admin_password

    encryption_secret="$(
        read_required_secret "$KEY_SECRET_FILE" "Registry key encryption secret"
    )" || return 1
    control_token="$(
        read_required_secret "$CONTROL_TOKEN_FILE" "Registry control token"
    )" || return 1
    export PPAASS_PROXY_REGISTRY_KEY_ENCRYPTION_SECRET="$encryption_secret"
    export PPAASS_PROXY_REGISTRY_CONTROL_TOKEN="$control_token"

    if [ -r "$ADMIN_PASSWORD_FILE" ]; then
        admin_password="$(cat "$ADMIN_PASSWORD_FILE")"
        if [ "${#admin_password}" -lt 8 ] || [ "${#admin_password}" -gt 256 ]; then
            echo "Error: Registry admin password must contain 8..=256 bytes." >&2
            return 1
        fi
        export PPAASS_PROXY_REGISTRY_BOOTSTRAP_ADMIN_PASSWORD="$admin_password"
    else
        unset PPAASS_PROXY_REGISTRY_BOOTSTRAP_ADMIN_PASSWORD 2>/dev/null || true
    fi
}

validate_runtime_files() {
    local public_key frontend
    public_key="${PPAASS_PROXY_REGISTRY_PROXY_IDENTITY_PUBLIC_KEY:-data/proxy-identity-public.pem}"
    frontend="${PPAASS_PROXY_REGISTRY_FRONTEND_DIST:-proxy-registry-frontend}"
    if [ ! -x ./proxy-registry ]; then
        echo "Error: ./proxy-registry is missing or not executable." >&2
        return 1
    fi
    if [ ! -f "$frontend/index.html" ]; then
        echo "Error: Registry frontend index is missing: $frontend/index.html" >&2
        return 1
    fi
    if [ -L "$public_key" ] || [ ! -r "$public_key" ] || [ ! -f "$public_key" ]; then
        echo "Error: Registry requires a provisioned Proxy identity public key: $public_key" >&2
        return 1
    fi
    if ! command -v openssl >/dev/null 2>&1 \
        || ! openssl pkey -pubin -in "$public_key" -noout >/dev/null 2>&1; then
        echo "Error: Proxy identity public key is invalid: $public_key" >&2
        return 1
    fi
}

permission_args() {
    local name="$1"
    local enabled="$2"
    local argument="$3"
    case "$enabled" in
        true) printf '%s\n' "$argument" ;;
        false) ;;
        *)
            echo "Error: $name must be true or false." >&2
            return 1
            ;;
    esac
}

run_proxy_registry() {
    local listen control_listen database access_database public_key frontend
    local database_permission access_permission

    load_runtime_environment
    load_secret_environment || exit 1
    validate_runtime_files || exit 1
    listen="${PPAASS_PROXY_REGISTRY_LISTEN_ADDR:-127.0.0.1:8787}"
    control_listen="${PPAASS_PROXY_REGISTRY_CONTROL_LISTEN_ADDR:-127.0.0.1:8797}"
    database="${PPAASS_PROXY_REGISTRY_DATABASE:-data/proxy-users.sqlite3}"
    access_database="${PPAASS_PROXY_REGISTRY_ACCESS_LOG_DATABASE:-data/proxy-access.sqlite3}"
    public_key="${PPAASS_PROXY_REGISTRY_PROXY_IDENTITY_PUBLIC_KEY:-data/proxy-identity-public.pem}"
    frontend="${PPAASS_PROXY_REGISTRY_FRONTEND_DIST:-proxy-registry-frontend}"
    database_permission="$(
        permission_args PPAASS_PROXY_REGISTRY_DATABASE_GROUP_READABLE \
            "${PPAASS_PROXY_REGISTRY_DATABASE_GROUP_READABLE:-false}" \
            --database-group-readable
    )" || exit 1
    access_permission="$(
        permission_args PPAASS_PROXY_REGISTRY_ACCESS_LOG_DATABASE_GROUP_WRITABLE \
            "${PPAASS_PROXY_REGISTRY_ACCESS_LOG_DATABASE_GROUP_WRITABLE:-false}" \
            --access-log-database-group-writable
    )" || exit 1
    mkdir -p "$LOG_DIR" "$(dirname "$database")" "$(dirname "$access_database")"

    local -a args=(
        --listen "$listen"
        --control-listen "$control_listen"
        --database "$database"
        --access-log-database "$access_database"
        --proxy-identity-public-key "$public_key"
        --frontend-dist "$frontend"
    )
    [ -n "$database_permission" ] && args+=("$database_permission")
    [ -n "$access_permission" ] && args+=("$access_permission")
    exec ./proxy-registry "${args[@]}"
}

wait_for_health() {
    local timeout="${PPAASS_PROXY_REGISTRY_HEALTH_TIMEOUT:-60}"
    local listen control_listen deadline

    load_runtime_environment
    listen="${PPAASS_PROXY_REGISTRY_LISTEN_ADDR:-127.0.0.1:8787}"
    control_listen="${PPAASS_PROXY_REGISTRY_CONTROL_LISTEN_ADDR:-127.0.0.1:8797}"
    case "$timeout" in
        ''|*[!0-9]*|0)
            echo "Error: health timeout must be a positive integer." >&2
            return 1
            ;;
    esac
    deadline=$((SECONDS + timeout))
    while [ "$SECONDS" -lt "$deadline" ]; do
        if curl --fail --silent --noproxy '*' --max-time 2 \
            "http://$listen/healthz" >/dev/null 2>&1 \
            && curl --fail --silent --noproxy '*' --max-time 2 \
                "http://$control_listen/control/v1/health" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    echo "Error: Registry did not become healthy within ${timeout}s." >&2
    return 1
}

stop_proxy_registry() {
    local pid
    pid="$(read_pid)"
    if ! is_running "$pid"; then
        rm -f "$PID_FILE"
        echo "Proxy Registry is not running."
        return 0
    fi
    kill "$pid" 2>/dev/null || true
    for _ in $(seq 1 10); do
        is_running "$pid" || break
        sleep 1
    done
    if is_running "$pid"; then
        kill -9 "$pid" 2>/dev/null || true
    fi
    rm -f "$PID_FILE"
}

start_proxy_registry() {
    local pid
    mkdir -p "$LOG_DIR"
    stop_proxy_registry >/dev/null
    nohup bash "$SCRIPT_PATH" run >"$LOG_DIR/proxy-registry.out" 2>&1 &
    pid=$!
    printf '%s\n' "$pid" >"$PID_FILE"
    if ! wait_for_health; then
        echo "Registry failed to start; see $LOG_DIR/proxy-registry.out" >&2
        stop_proxy_registry
        return 1
    fi
    echo "Proxy Registry started with PID $pid"
}

status_proxy_registry() {
    local pid
    pid="$(read_pid)"
    if is_running "$pid"; then
        echo "Proxy Registry is running with PID $pid"
    else
        echo "Proxy Registry is not running"
        return 1
    fi
}

case "${1:-start}" in
    run) run_proxy_registry ;;
    wait-health) wait_for_health ;;
    start) start_proxy_registry ;;
    restart)
        stop_proxy_registry
        start_proxy_registry
        ;;
    stop) stop_proxy_registry ;;
    status) status_proxy_registry ;;
    *)
        echo "Usage: $0 [run|wait-health|start|restart|stop|status]"
        exit 1
        ;;
esac
