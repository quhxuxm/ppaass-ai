#!/bin/bash
# Start Proxy Web (Linux)
# Assumes proxy-web, proxy-web.env, users.toml, and proxy-web-frontend are in
# the same deployment directory as this script.
#
# Usage:
#   ./start-proxy-web.sh          Start/restart Proxy Web in background
#   ./start-proxy-web.sh run      Run Proxy Web in the foreground (systemd)
#   ./start-proxy-web.sh stop     Stop the background process
#   ./start-proxy-web.sh status   Show process status
#   ./start-proxy-web.sh restart  Restart the background process

set -u

SCRIPT_PATH="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR" || exit 1

LOG_DIR="logs"
PID_FILE="$LOG_DIR/proxy-web.pid"
START_TIMEOUT="${PROXY_WEB_START_TIMEOUT:-20}"
RUNTIME_ENV_FILE="${PPAASS_PROXY_WEB_RUNTIME_ENV_FILE:-proxy-web.env}"
SECRET_DIR="${PPAASS_PROXY_WEB_SECRET_DIR:-.secrets}"
KEY_SECRET_FILE="$SECRET_DIR/proxy-web-key-encryption-secret"
ADMIN_PASSWORD_FILE="$SECRET_DIR/proxy-web-admin-password"

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
    if [ ! -f "./users.toml" ]; then
        echo "Error: ./users.toml is missing." >&2
        return 1
    fi
    if [ ! -f "./proxy-web-frontend/index.html" ]; then
        echo "Error: ./proxy-web-frontend/index.html is missing." >&2
        return 1
    fi
}

run_proxy_web() {
    local listen_addr database_path users_toml_path frontend_dist

    load_runtime_environment
    load_secret_environment || exit 1
    ensure_runtime_files || exit 1

    listen_addr="${PPAASS_PROXY_WEB_LISTEN_ADDR:-127.0.0.1:8787}"
    database_path="${PPAASS_PROXY_WEB_DATABASE:-data/proxy-users.sqlite3}"
    users_toml_path="${PPAASS_PROXY_WEB_USERS_TOML:-users.toml}"
    frontend_dist="${PPAASS_PROXY_WEB_FRONTEND_DIST:-proxy-web-frontend}"
    mkdir -p "$LOG_DIR" "$(dirname "$database_path")"
    exec ./proxy-web \
        --listen "$listen_addr" \
        --database "$database_path" \
        --users-toml "$users_toml_path" \
        --frontend-dist "$frontend_dist"
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
    *)
        echo "Usage: $0 [start|run|stop|status|restart]"
        exit 1
        ;;
esac
