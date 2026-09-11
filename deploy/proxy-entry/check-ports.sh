#!/bin/bash

managed_entry_pids() {
    local service
    local pid
    local services="ppaass-proxy-entry.service"
    services="$services $(
        systemctl list-units --type=service --state=running \
            'ppaass-proxy-entry@*.service' --no-legend --plain 2>/dev/null |
            awk '{print $1}'
    )"
    for service in $services; do
        pid="$(systemctl show "$service" --property MainPID --value 2>/dev/null || true)"
        if [[ "$pid" =~ ^[1-9][0-9]*$ ]]; then
            printf '%s\n' "$pid"
        fi
    done
}

check_entry_ports_available() {
    local count="${1:?instance count is required}"
    shift
    local managed_pids=" $* "
    local instance
    local port
    local listeners
    local line
    local listener_pids
    local pid_marker
    local pid
    local conflict=0

    for instance in $(seq 1 "$count"); do
        port="$(proxy_instance_port "$instance")"
        listeners="$({
            ss -H -ltnp "sport = :$port"
            ss -H -lunp "sport = :$port"
        } 2>/dev/null)"
        [ -n "$listeners" ] || continue
        while IFS= read -r line; do
            listener_pids="$(printf '%s\n' "$line" | grep -o 'pid=[0-9]*' || true)"
            if [ -z "$listener_pids" ]; then
                printf 'Port %s is occupied by an unidentified listener: %s\n' \
                    "$port" "$line" >&2
                conflict=1
                continue
            fi
            for pid_marker in $listener_pids; do
                pid="${pid_marker#pid=}"
                case "$managed_pids" in
                    *" $pid "*) ;;
                    *)
                        printf 'Port %s conflicts with another process (PID %s): %s\n' \
                            "$port" "$pid" "$line" >&2
                        conflict=1
                        ;;
                esac
            done
        done <<<"$listeners"
    done
    [ "$conflict" = 0 ]
}
