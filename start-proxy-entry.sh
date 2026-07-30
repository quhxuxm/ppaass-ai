#!/bin/bash
# Start Proxy Entry (Linux)
# Assumes proxy-entry binary and proxy-entry.toml are in the same directory as this script.
#
# Usage:
#   ./start-proxy-entry.sh          Start/restart the proxy supervisor in background
#   ./start-proxy-entry.sh stop     Stop the supervisor and proxy process
#   ./start-proxy-entry.sh status   Show supervisor/proxy process status
#   ./start-proxy-entry.sh restart  Restart the supervisor
#
# Optional environment variables:
#   PROXY_ENTRY_CONFIG=proxy-entry.toml        Override config path
#   PPAASS_PROXY_ENTRY_LOG_DIR=logs      Override supervisor log/PID directory
#   PROXY_ENTRY_RESTART_DELAY=3          Seconds to wait before restarting proxy
#   PROXY_ENTRY_START_TIMEOUT=15         Seconds to wait for startup verification

set -u

SCRIPT_PATH="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR" || exit 1

LOG_DIR="${PPAASS_PROXY_ENTRY_LOG_DIR:-logs}"
SUPERVISOR_PID_FILE="$LOG_DIR/proxy-entry-supervisor.pid"
PROXY_PID_FILE="$LOG_DIR/proxy-entry.pid"
CONFIG_PATH="${PROXY_ENTRY_CONFIG:-proxy-entry.toml}"
RESTART_DELAY="${PROXY_ENTRY_RESTART_DELAY:-3}"
START_TIMEOUT="${PROXY_ENTRY_START_TIMEOUT:-15}"
IDENTITY_PRIVATE_KEY="${PPAASS_PROXY_ENTRY_IDENTITY_PRIVATE_KEY:-data/proxy-identity-private.pem}"
IDENTITY_PUBLIC_KEY="${PPAASS_PROXY_ENTRY_IDENTITY_PUBLIC_KEY:-data/proxy-identity-public.pem}"

read_pid() {
    local pid_file="$1"
    if [ -f "$pid_file" ]; then
        tr -d '[:space:]' < "$pid_file"
    fi
}

is_running() {
    local pid="${1:-}"
    [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null
}

ensure_proxy_binary() {
    if [ ! -f "./proxy-entry" ]; then
        echo "Error: ./proxy-entry binary not found in script directory." >&2
        return 1
    fi

    if [ ! -x "./proxy-entry" ]; then
        chmod +x ./proxy-entry 2>/dev/null || true
    fi

    if [ ! -x "./proxy-entry" ]; then
        echo "Error: ./proxy-entry binary is not executable." >&2
        return 1
    fi

    return 0
}

ensure_proxy_identity() {
    local identity_file private_key_dir public_key_dir
    local temporary_private_key temporary_public_key

    if ! command -v openssl >/dev/null 2>&1; then
        echo "Error: openssl is required for the Proxy transport identity." >&2
        return 1
    fi
    for identity_file in "$IDENTITY_PRIVATE_KEY" "$IDENTITY_PUBLIC_KEY"; do
        if [ -L "$identity_file" ]; then
            echo "Error: refusing symlinked Proxy identity file: $identity_file" >&2
            return 1
        fi
        if [ -e "$identity_file" ] && [ ! -f "$identity_file" ]; then
            echo "Error: Proxy identity path is not a regular file: $identity_file" >&2
            return 1
        fi
    done

    private_key_dir="$(dirname "$IDENTITY_PRIVATE_KEY")"
    public_key_dir="$(dirname "$IDENTITY_PUBLIC_KEY")"
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

    # Local launches keep the public key synchronized. In production the
    # Proxy UID cannot overwrite the root/Web-owned public file.
    if [ ! -e "$IDENTITY_PUBLIC_KEY" ] || [ -w "$IDENTITY_PUBLIC_KEY" ]; then
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
        mv -f "$temporary_public_key" "$IDENTITY_PUBLIC_KEY"
    fi
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

stop_pid_file() {
    local pid_file="$1"
    local label="$2"
    local pid
    pid="$(read_pid "$pid_file")"

    if is_running "$pid"; then
        echo "Stopping $label process: $pid"
        kill "$pid" 2>/dev/null || true
        if ! wait_for_exit "$pid" 10; then
            echo "Force killing $label process: $pid"
            kill -9 "$pid" 2>/dev/null || true
        fi
    fi

    rm -f "$pid_file"
}

stop_supervisor_processes() {
    local existing_pids
    existing_pids="$(pgrep -f "start-proxy-entry.sh --supervisor" || true)"

    if [ -n "$existing_pids" ]; then
        echo "Stopping existing Proxy Entry supervisor process(es): $existing_pids"
        kill $existing_pids 2>/dev/null || true
        sleep 2

        local still_running
        still_running="$(pgrep -f "start-proxy-entry.sh --supervisor" || true)"
        if [ -n "$still_running" ]; then
            echo "Force killing Proxy Entry supervisor process(es): $still_running"
            kill -9 $still_running 2>/dev/null || true
        fi
    fi
}

stop_legacy_proxy_processes() {
    local existing_pids
    existing_pids="$(pgrep -f '(^|[[:space:]])\./proxy-entry([[:space:]]|$)' || true)"

    if [ -n "$existing_pids" ]; then
        echo "Stopping existing Proxy Entry process(es): $existing_pids"
        kill $existing_pids 2>/dev/null || true
        sleep 2

        local still_running
        still_running="$(pgrep -f '(^|[[:space:]])\./proxy-entry([[:space:]]|$)' || true)"
        if [ -n "$still_running" ]; then
            echo "Force killing Proxy Entry process(es): $still_running"
            kill -9 $still_running 2>/dev/null || true
        fi
    fi
}

stop_proxy() {
    stop_pid_file "$SUPERVISOR_PID_FILE" "Proxy Entry supervisor"
    stop_pid_file "$PROXY_PID_FILE" "Proxy"
    stop_supervisor_processes
    stop_legacy_proxy_processes
}

status_proxy() {
    local supervisor_pid proxy_pid
    supervisor_pid="$(read_pid "$SUPERVISOR_PID_FILE")"
    proxy_pid="$(read_pid "$PROXY_PID_FILE")"

    if is_running "$supervisor_pid"; then
        echo "Proxy Entry supervisor is running with PID $supervisor_pid"
    else
        echo "Proxy Entry supervisor is not running"
    fi

    if is_running "$proxy_pid"; then
        echo "Proxy Entry process is running with PID $proxy_pid"
    else
        echo "Proxy Entry process is not running"
    fi
}

tail_proxy_start_log() {
    if [ -f "$LOG_DIR/proxy-entry.out" ]; then
        echo "Last proxy supervisor log lines:" >&2
        tail -n 80 "$LOG_DIR/proxy-entry.out" >&2
    fi
}

wait_for_start() {
    local timeout_secs="${1:-15}"
    local elapsed=0
    local supervisor_pid proxy_pid

    while [ "$elapsed" -lt "$timeout_secs" ]; do
        supervisor_pid="$(read_pid "$SUPERVISOR_PID_FILE")"
        proxy_pid="$(read_pid "$PROXY_PID_FILE")"

        if is_running "$supervisor_pid" && is_running "$proxy_pid"; then
            return 0
        fi

        sleep 1
        elapsed=$((elapsed + 1))
    done

    echo "Error: Proxy Entry did not start within ${timeout_secs}s." >&2
    status_proxy >&2
    tail_proxy_start_log
    return 1
}

start_detached_supervisor() {
    if command -v setsid >/dev/null 2>&1; then
        nohup setsid bash "$SCRIPT_PATH" --supervisor > "$LOG_DIR/proxy-entry.out" 2>&1 &
    else
        nohup bash "$SCRIPT_PATH" --supervisor > "$LOG_DIR/proxy-entry.out" 2>&1 &
    fi
}

run_supervisor() {
    local stop_requested=0
    local child_pid=""
    local sleep_pid=""

    mkdir -p "$LOG_DIR"
    echo "$$" > "$SUPERVISOR_PID_FILE"

    request_stop() {
        stop_requested=1
        echo "$(date '+%Y-%m-%d %H:%M:%S') Stop requested, shutting down proxy supervisor..."

        if is_running "$child_pid"; then
            kill "$child_pid" 2>/dev/null || true
        fi
        if is_running "$sleep_pid"; then
            kill "$sleep_pid" 2>/dev/null || true
        fi
    }

    trap request_stop INT TERM

    while [ "$stop_requested" -eq 0 ]; do
        if ! ensure_proxy_binary || ! ensure_proxy_identity; then
            break
        fi

        if [ -n "$CONFIG_PATH" ] && [ -f "$CONFIG_PATH" ]; then
            echo "$(date '+%Y-%m-%d %H:%M:%S') Starting Proxy Entry with config $CONFIG_PATH..."
            ./proxy-entry --config "$CONFIG_PATH" &
        else
            echo "$(date '+%Y-%m-%d %H:%M:%S') Warning: proxy-entry.toml not found. Starting without --config."
            ./proxy-entry &
        fi

        child_pid=$!
        echo "$child_pid" > "$PROXY_PID_FILE"
        echo "$(date '+%Y-%m-%d %H:%M:%S') Proxy Entry started with PID $child_pid"

        wait "$child_pid"
        exit_code=$?
        rm -f "$PROXY_PID_FILE"

        if [ "$stop_requested" -ne 0 ]; then
            break
        fi

        echo "$(date '+%Y-%m-%d %H:%M:%S') Proxy Entry exited with code $exit_code; restarting in ${RESTART_DELAY}s..."
        sleep "$RESTART_DELAY" &
        sleep_pid=$!
        wait "$sleep_pid" 2>/dev/null || true
        sleep_pid=""
    done

    rm -f "$SUPERVISOR_PID_FILE" "$PROXY_PID_FILE"
    echo "$(date '+%Y-%m-%d %H:%M:%S') Proxy Entry supervisor stopped."
}

start_proxy() {
    if ! ensure_proxy_binary || ! ensure_proxy_identity; then
        exit 1
    fi

    mkdir -p "$LOG_DIR"
    stop_proxy

    echo "Starting Proxy Entry supervisor..."
    start_detached_supervisor
    echo "$!" > "$SUPERVISOR_PID_FILE"
    echo "Proxy Entry supervisor started with PID $!"
    echo "Logs: $SCRIPT_DIR/$LOG_DIR/proxy-entry.out"

    if ! wait_for_start "$START_TIMEOUT"; then
        return 1
    fi

    status_proxy
}

case "${1:-start}" in
    --supervisor)
        run_supervisor
        ;;
    start)
        start_proxy
        ;;
    restart)
        stop_proxy
        start_proxy
        ;;
    stop)
        stop_proxy
        ;;
    status)
        status_proxy
        ;;
    *)
        echo "Usage: $0 [start|stop|status|restart]"
        exit 1
        ;;
esac
