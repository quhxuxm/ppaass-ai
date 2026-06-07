#!/bin/bash
# Start Proxy (Linux)
# Assumes proxy binary and proxy.toml are in the same directory as this script.
#
# Usage:
#   ./start-proxy.sh          Start/restart the proxy supervisor in background
#   ./start-proxy.sh stop     Stop the supervisor and proxy process
#   ./start-proxy.sh status   Show supervisor/proxy process status
#   ./start-proxy.sh restart  Restart the supervisor
#
# Optional environment variables:
#   PROXY_CONFIG=proxy.toml        Override config path
#   PROXY_RESTART_DELAY=3          Seconds to wait before restarting proxy
#   PROXY_START_TIMEOUT=15         Seconds to wait for startup verification

set -u

SCRIPT_PATH="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR" || exit 1

LOG_DIR="logs"
SUPERVISOR_PID_FILE="$LOG_DIR/proxy-supervisor.pid"
PROXY_PID_FILE="$LOG_DIR/proxy.pid"
CONFIG_PATH="${PROXY_CONFIG:-proxy.toml}"
RESTART_DELAY="${PROXY_RESTART_DELAY:-3}"
START_TIMEOUT="${PROXY_START_TIMEOUT:-15}"

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
    if [ ! -f "./proxy" ]; then
        echo "Error: ./proxy binary not found in script directory." >&2
        return 1
    fi

    if [ ! -x "./proxy" ]; then
        chmod +x ./proxy 2>/dev/null || true
    fi

    if [ ! -x "./proxy" ]; then
        echo "Error: ./proxy binary is not executable." >&2
        return 1
    fi

    return 0
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
    existing_pids="$(pgrep -f "start-proxy.sh --supervisor" || true)"

    if [ -n "$existing_pids" ]; then
        echo "Stopping existing Proxy supervisor process(es): $existing_pids"
        kill $existing_pids 2>/dev/null || true
        sleep 2

        local still_running
        still_running="$(pgrep -f "start-proxy.sh --supervisor" || true)"
        if [ -n "$still_running" ]; then
            echo "Force killing Proxy supervisor process(es): $still_running"
            kill -9 $still_running 2>/dev/null || true
        fi
    fi
}

stop_legacy_proxy_processes() {
    local existing_pids
    existing_pids="$(pgrep -f "./proxy" || true)"

    if [ -n "$existing_pids" ]; then
        echo "Stopping existing Proxy process(es): $existing_pids"
        kill $existing_pids 2>/dev/null || true
        sleep 2

        local still_running
        still_running="$(pgrep -f "./proxy" || true)"
        if [ -n "$still_running" ]; then
            echo "Force killing Proxy process(es): $still_running"
            kill -9 $still_running 2>/dev/null || true
        fi
    fi
}

stop_proxy() {
    stop_pid_file "$SUPERVISOR_PID_FILE" "Proxy supervisor"
    stop_pid_file "$PROXY_PID_FILE" "Proxy"
    stop_supervisor_processes
    stop_legacy_proxy_processes
}

status_proxy() {
    local supervisor_pid proxy_pid
    supervisor_pid="$(read_pid "$SUPERVISOR_PID_FILE")"
    proxy_pid="$(read_pid "$PROXY_PID_FILE")"

    if is_running "$supervisor_pid"; then
        echo "Proxy supervisor is running with PID $supervisor_pid"
    else
        echo "Proxy supervisor is not running"
    fi

    if is_running "$proxy_pid"; then
        echo "Proxy process is running with PID $proxy_pid"
    else
        echo "Proxy process is not running"
    fi
}

tail_proxy_start_log() {
    if [ -f "$LOG_DIR/proxy.out" ]; then
        echo "Last proxy supervisor log lines:" >&2
        tail -n 80 "$LOG_DIR/proxy.out" >&2
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

    echo "Error: Proxy did not start within ${timeout_secs}s." >&2
    status_proxy >&2
    tail_proxy_start_log
    return 1
}

start_detached_supervisor() {
    if command -v setsid >/dev/null 2>&1; then
        nohup setsid bash "$SCRIPT_PATH" --supervisor > "$LOG_DIR/proxy.out" 2>&1 &
    else
        nohup bash "$SCRIPT_PATH" --supervisor > "$LOG_DIR/proxy.out" 2>&1 &
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
        if ! ensure_proxy_binary; then
            break
        fi

        if [ -n "$CONFIG_PATH" ] && [ -f "$CONFIG_PATH" ]; then
            echo "$(date '+%Y-%m-%d %H:%M:%S') Starting Proxy with config $CONFIG_PATH..."
            ./proxy --config "$CONFIG_PATH" &
        else
            echo "$(date '+%Y-%m-%d %H:%M:%S') Warning: proxy.toml not found. Starting without --config."
            ./proxy &
        fi

        child_pid=$!
        echo "$child_pid" > "$PROXY_PID_FILE"
        echo "$(date '+%Y-%m-%d %H:%M:%S') Proxy started with PID $child_pid"

        wait "$child_pid"
        exit_code=$?
        rm -f "$PROXY_PID_FILE"

        if [ "$stop_requested" -ne 0 ]; then
            break
        fi

        echo "$(date '+%Y-%m-%d %H:%M:%S') Proxy exited with code $exit_code; restarting in ${RESTART_DELAY}s..."
        sleep "$RESTART_DELAY" &
        sleep_pid=$!
        wait "$sleep_pid" 2>/dev/null || true
        sleep_pid=""
    done

    rm -f "$SUPERVISOR_PID_FILE" "$PROXY_PID_FILE"
    echo "$(date '+%Y-%m-%d %H:%M:%S') Proxy supervisor stopped."
}

start_proxy() {
    if ! ensure_proxy_binary; then
        exit 1
    fi

    mkdir -p "$LOG_DIR"
    stop_proxy

    echo "Starting Proxy supervisor..."
    start_detached_supervisor
    echo "$!" > "$SUPERVISOR_PID_FILE"
    echo "Proxy supervisor started with PID $!"
    echo "Logs: $SCRIPT_DIR/$LOG_DIR/proxy.out"

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
