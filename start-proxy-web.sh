#!/bin/bash
# Start Proxy Web (Linux)
# Assumes proxy-web, proxy-web.env, and proxy-web-frontend are in
# the same deployment directory as this script.
#
# Usage:
#   ./start-proxy-web.sh          Start/restart Proxy Web in background
#   ./start-proxy-web.sh run      Run Proxy Web in the foreground (systemd)
#   ./start-proxy-web.sh wait-health
#                                 Wait for the local health endpoint (systemd)
#   ./start-proxy-web.sh stop     Stop the background process
#   ./start-proxy-web.sh status   Show process status
#   ./start-proxy-web.sh restart  Restart the background process
#
# PPAASS_PROXY_WEB_LOG_DIR can override the background log/PID directory.
# Production keeps the user database group-readable and uses a separate,
# group-writable access-log database shared by Proxy and Proxy Web.

set -u

SCRIPT_PATH="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR" || exit 1

LOG_DIR="${PPAASS_PROXY_WEB_LOG_DIR:-logs}"
PID_FILE="$LOG_DIR/proxy-web.pid"
START_TIMEOUT="${PROXY_WEB_START_TIMEOUT:-20}"
RUNTIME_ENV_FILE="${PPAASS_PROXY_WEB_RUNTIME_ENV_FILE:-proxy-web.env}"
SECRET_DIR="${PPAASS_PROXY_WEB_SECRET_DIR:-.secrets}"
KEY_SECRET_FILE="$SECRET_DIR/proxy-web-key-encryption-secret"
ADMIN_PASSWORD_FILE="$SECRET_DIR/proxy-web-admin-password"
IDENTITY_PRIVATE_KEY="${PPAASS_PROXY_IDENTITY_PRIVATE_KEY:-data/proxy-identity-private.pem}"

read_pid() {
    if [ -f "$PID_FILE" ]; then
        tr -d '[:space:]' < "$PID_FILE"
    fi
}

is_running() {
    local pid="${1:-}"
    [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null
}

wait_for_exit() {
    local pid="$1"
    local timeout_secs="${2:-10}"
    local elapsed=0

    while is_running "$pid" && [ "$elapsed" -lt "$timeout_secs" ]; do
        sleep 1
        elapsed=$((elapsed + 1))
    done

    ! is_running "$pid"
}

find_deploy_processes() {
    local executable_link executable pid

    for executable_link in /proc/[0-9]*/exe; do
        executable="$(readlink "$executable_link" 2>/dev/null || true)"
        executable="${executable% (deleted)}"
        if [ "$executable" = "$SCRIPT_DIR/proxy-web" ]; then
            pid="${executable_link#/proc/}"
            printf '%s\n' "${pid%/exe}"
        fi
    done
}

stop_proxy_web() {
    local pid existing_pids
    pid="$(read_pid)"

    if is_running "$pid"; then
        echo "Stopping Proxy Web process: $pid"
        kill "$pid" 2>/dev/null || true
        if ! wait_for_exit "$pid" 10; then
            echo "Force killing Proxy Web process: $pid"
            kill -9 "$pid" 2>/dev/null || true
        fi
    fi
    rm -f "$PID_FILE"

    existing_pids="$(find_deploy_processes)"
    if [ -n "$existing_pids" ]; then
        echo "Stopping remaining Proxy Web process(es): $existing_pids"
        kill $existing_pids 2>/dev/null || true
        sleep 2
        existing_pids="$(find_deploy_processes)"
        if [ -n "$existing_pids" ]; then
            echo "Force killing remaining Proxy Web process(es): $existing_pids"
            kill -9 $existing_pids 2>/dev/null || true
        fi
    fi
}

load_runtime_environment() {
    if [ -f "$RUNTIME_ENV_FILE" ]; then
        set -a
        # shellcheck disable=SC1090
        . "$RUNTIME_ENV_FILE"
        set +a
    fi
}

load_secret_environment() {
    local encryption_secret encryption_secret_bytes
    local admin_password admin_password_bytes

    if [ ! -r "$KEY_SECRET_FILE" ]; then
        echo "Error: $KEY_SECRET_FILE is missing or unreadable." >&2
        return 1
    fi
    encryption_secret="$(cat "$KEY_SECRET_FILE")"
    encryption_secret_bytes="$(printf '%s' "$encryption_secret" | wc -c | tr -d '[:space:]')"
    if [ "$encryption_secret_bytes" -lt 32 ]; then
        echo "Error: Proxy Web key encryption secret must contain at least 32 bytes." >&2
        return 1
    fi
    export PPAASS_PROXY_WEB_KEY_ENCRYPTION_SECRET="$encryption_secret"

    if [ -r "$ADMIN_PASSWORD_FILE" ]; then
        admin_password="$(cat "$ADMIN_PASSWORD_FILE")"
        admin_password_bytes="$(printf '%s' "$admin_password" | wc -c | tr -d '[:space:]')"
        if [ "$admin_password_bytes" -eq 0 ] || [ "$admin_password_bytes" -gt 256 ]; then
            echo "Error: Proxy Web admin password must contain at most 256 UTF-8 bytes." >&2
            return 1
        fi
        export PPAASS_PROXY_WEB_BOOTSTRAP_ADMIN_PASSWORD="$admin_password"
    else
        unset PPAASS_PROXY_WEB_BOOTSTRAP_ADMIN_PASSWORD 2>/dev/null || true
    fi

}

ensure_runtime_files() {
    if [ ! -x "./proxy-web" ]; then
        echo "Error: ./proxy-web is missing or not executable." >&2
        return 1
    fi
    if [ ! -f "./proxy-web-frontend/index.html" ]; then
        echo "Error: ./proxy-web-frontend/index.html is missing." >&2
        return 1
    fi
}

ensure_proxy_identity_public_key() {
    local public_key="$1"
    local identity_file private_key_dir public_key_dir
    local temporary_private_key temporary_public_key

    if ! command -v openssl >/dev/null 2>&1; then
        echo "Error: openssl is required for the Proxy transport identity." >&2
        return 1
    fi
    for identity_file in "$IDENTITY_PRIVATE_KEY" "$public_key"; do
        if [ -L "$identity_file" ]; then
            echo "Error: refusing symlinked Proxy identity file: $identity_file" >&2
            return 1
        fi
        if [ -e "$identity_file" ] && [ ! -f "$identity_file" ]; then
            echo "Error: Proxy identity path is not a regular file: $identity_file" >&2
            return 1
        fi
    done

    # The production Web UID cannot read the private identity and only needs
    # the public file provisioned by the deployment workflow.
    if [ -r "$public_key" ] && [ ! -r "$IDENTITY_PRIVATE_KEY" ]; then
        if openssl pkey -pubin -in "$public_key" -noout >/dev/null 2>&1; then
            return 0
        fi
        echo "Error: Proxy transport identity public key is invalid." >&2
        return 1
    fi

    private_key_dir="$(dirname "$IDENTITY_PRIVATE_KEY")"
    public_key_dir="$(dirname "$public_key")"
    mkdir -p "$private_key_dir" "$public_key_dir"
    if [ ! -e "$IDENTITY_PRIVATE_KEY" ]; then
        temporary_private_key="$(mktemp "$private_key_dir/.proxy-identity-private.XXXXXX")" \
            || return 1
        if ! (
            umask 077
            openssl genpkey \
                -algorithm RSA \
                -pkeyopt rsa_keygen_bits:3072 \
                -out "$temporary_private_key" >/dev/null 2>&1
        ); then
            rm -f "$temporary_private_key"
            echo "Error: failed to generate the Proxy transport identity." >&2
            return 1
        fi
        chmod 0600 "$temporary_private_key"
        if ln "$temporary_private_key" "$IDENTITY_PRIVATE_KEY" 2>/dev/null; then
            echo "Generated persistent local Proxy transport identity: $IDENTITY_PRIVATE_KEY"
        fi
        rm -f "$temporary_private_key"
    fi
    if [ ! -r "$IDENTITY_PRIVATE_KEY" ] \
        || ! openssl rsa -in "$IDENTITY_PRIVATE_KEY" -check -noout >/dev/null 2>&1; then
        echo "Error: Proxy transport identity private key is unreadable or invalid." >&2
        return 1
    fi
    chmod 0600 "$IDENTITY_PRIVATE_KEY" 2>/dev/null || true

    temporary_public_key="$(mktemp "$public_key_dir/.proxy-identity-public.XXXXXX")" \
        || return 1
    if ! openssl pkey \
        -in "$IDENTITY_PRIVATE_KEY" \
        -pubout \
        -out "$temporary_public_key" 2>/dev/null; then
        rm -f "$temporary_public_key"
        echo "Error: failed to derive the Proxy transport identity public key." >&2
        return 1
    fi
    chmod 0644 "$temporary_public_key"
    mv -f "$temporary_public_key" "$public_key"
}

run_proxy_web() {
    local listen_addr database_path access_log_database_path proxy_identity_public_key frontend_dist
    local database_group_readable access_log_database_group_writable
    local -a database_permission_args=()
    local -a access_log_database_permission_args=()

    load_runtime_environment
    proxy_identity_public_key="${PPAASS_PROXY_WEB_PROXY_IDENTITY_PUBLIC_KEY:-data/proxy-identity-public.pem}"
    load_secret_environment || exit 1
    ensure_runtime_files || exit 1
    ensure_proxy_identity_public_key "$proxy_identity_public_key" || exit 1

    listen_addr="${PPAASS_PROXY_WEB_LISTEN_ADDR:-127.0.0.1:8787}"
    database_path="${PPAASS_PROXY_WEB_DATABASE:-data/proxy-users.sqlite3}"
    access_log_database_path="${PPAASS_PROXY_WEB_ACCESS_LOG_DATABASE:-data/proxy-access.sqlite3}"
    frontend_dist="${PPAASS_PROXY_WEB_FRONTEND_DIST:-proxy-web-frontend}"
    database_group_readable="${PPAASS_PROXY_WEB_DATABASE_GROUP_READABLE:-false}"
    case "$database_group_readable" in
        true)
            database_permission_args+=(--database-group-readable)
            ;;
        false)
            ;;
        *)
            echo "Error: PPAASS_PROXY_WEB_DATABASE_GROUP_READABLE must be true or false." >&2
            exit 1
            ;;
    esac
    access_log_database_group_writable="${PPAASS_PROXY_WEB_ACCESS_LOG_DATABASE_GROUP_WRITABLE:-false}"
    case "$access_log_database_group_writable" in
        true)
            access_log_database_permission_args+=(--access-log-database-group-writable)
            ;;
        false)
            ;;
        *)
            echo "Error: PPAASS_PROXY_WEB_ACCESS_LOG_DATABASE_GROUP_WRITABLE must be true or false." >&2
            exit 1
            ;;
    esac
    case "${PPAASS_PROXY_WEB_DATABASE_GROUP_WRITABLE:-false}" in
        false)
            ;;
        *)
            echo "Error: PPAASS_PROXY_WEB_DATABASE_GROUP_WRITABLE is obsolete; use the split database permission settings." >&2
            exit 1
            ;;
    esac
    mkdir -p \
        "$LOG_DIR" \
        "$(dirname "$database_path")" \
        "$(dirname "$access_log_database_path")"
    exec ./proxy-web \
        --listen "$listen_addr" \
        --database "$database_path" \
        "${database_permission_args[@]}" \
        --access-log-database "$access_log_database_path" \
        "${access_log_database_permission_args[@]}" \
        --proxy-identity-public-key "$proxy_identity_public_key" \
        --frontend-dist "$frontend_dist"
}

wait_for_proxy_web_health() {
    local timeout_seconds="${PPAASS_PROXY_WEB_HEALTH_TIMEOUT:-60}"
    local listen_addr="${PPAASS_PROXY_WEB_LISTEN_ADDR:-127.0.0.1:8787}"
    local deadline

    case "$timeout_seconds" in
        ''|*[!0-9]*|0)
            echo "Error: PPAASS_PROXY_WEB_HEALTH_TIMEOUT must be a positive integer." >&2
            return 1
            ;;
    esac
    if ! command -v curl >/dev/null 2>&1; then
        echo "Error: curl is required for the Proxy Web health check." >&2
        return 1
    fi

    deadline=$((SECONDS + timeout_seconds))
    while [ "$SECONDS" -lt "$deadline" ]; do
        if curl \
            --fail \
            --silent \
            --show-error \
            --noproxy '*' \
            --connect-timeout 1 \
            --max-time 2 \
            "http://$listen_addr/healthz" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done

    echo "Error: Proxy Web did not become healthy within ${timeout_seconds}s." >&2
    return 1
}

wait_for_start() {
    local pid="$1"
    local elapsed=0
    local listen_addr listen_port

    load_runtime_environment
    listen_addr="${PPAASS_PROXY_WEB_LISTEN_ADDR:-127.0.0.1:8787}"
    listen_port="${listen_addr##*:}"

    while [ "$elapsed" -lt "$START_TIMEOUT" ]; do
        if ! is_running "$pid"; then
            break
        fi
        if command -v curl >/dev/null 2>&1; then
            if curl --fail --silent --show-error \
                "http://127.0.0.1:$listen_port/healthz" >/dev/null 2>&1; then
                return 0
            fi
        else
            return 0
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done

    echo "Error: Proxy Web did not become healthy within ${START_TIMEOUT}s." >&2
    if [ -f "$LOG_DIR/proxy-web.out" ]; then
        tail -n 80 "$LOG_DIR/proxy-web.out" >&2
    fi
    return 1
}

start_proxy_web() {
    local pid

    ensure_runtime_files || exit 1
    mkdir -p "$LOG_DIR"
    stop_proxy_web

    echo "Starting Proxy Web..."
    if command -v setsid >/dev/null 2>&1; then
        nohup setsid bash "$SCRIPT_PATH" run > "$LOG_DIR/proxy-web.out" 2>&1 &
    else
        nohup bash "$SCRIPT_PATH" run > "$LOG_DIR/proxy-web.out" 2>&1 &
    fi
    pid=$!
    echo "$pid" > "$PID_FILE"

    if ! wait_for_start "$pid"; then
        stop_proxy_web
        return 1
    fi
    echo "Proxy Web is running with PID $pid"
    echo "Logs: $SCRIPT_DIR/$LOG_DIR/proxy-web.out"
}

status_proxy_web() {
    local pid
    pid="$(read_pid)"
    if is_running "$pid"; then
        echo "Proxy Web is running with PID $pid"
    else
        echo "Proxy Web is not running"
        return 1
    fi
}

case "${1:-start}" in
    run)
        run_proxy_web
        ;;
    start)
        start_proxy_web
        ;;
    restart)
        stop_proxy_web
        start_proxy_web
        ;;
    stop)
        stop_proxy_web
        ;;
    status)
        status_proxy_web
        ;;
    wait-health)
        wait_for_proxy_web_health
        ;;
    *)
        echo "Usage: $0 [start|run|stop|status|restart|wait-health]"
        exit 1
        ;;
esac
