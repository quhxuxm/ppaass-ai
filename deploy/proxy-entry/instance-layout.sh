#!/bin/bash

MAX_PROXY_ENTRY_INSTANCES=100

validate_instance_count() {
    local count="${1:-}"
    if [[ ! "$count" =~ ^[1-9][0-9]*$ ]] || \
       ((10#$count > MAX_PROXY_ENTRY_INSTANCES)); then
        echo "INSTANCE_COUNT must be an integer between 1 and $MAX_PROXY_ENTRY_INSTANCES." >&2
        return 2
    fi
}

validate_advertised_address() {
    local address="${1:-}"
    local port

    if [[ "$address" =~ ^([0-9A-Za-z._-]+):([0-9]{1,5})$ ]]; then
        port="${BASH_REMATCH[2]}"
        case "${BASH_REMATCH[1]}" in
            .*|*.|*..*)
                echo "ADVERTISED_ADDRESS contains an invalid host name." >&2
                return 2
                ;;
        esac
    elif [[ "$address" =~ ^\[([0-9A-Fa-f:.]+)\]:([0-9]{1,5})$ ]]; then
        port="${BASH_REMATCH[2]}"
    else
        echo "ADVERTISED_ADDRESS must be host:port or [IPv6]:port." >&2
        return 2
    fi

    if ((10#$port < 1 || 10#$port > 65535)); then
        echo "ADVERTISED_ADDRESS port must be between 1 and 65535." >&2
        return 2
    fi
}

validate_entry_id_for_instances() {
    local entry_id="${1:-}"
    local count="${2:-}"
    local final_id

    validate_instance_count "$count"
    case "$entry_id" in
        *[!0-9A-Za-z._:-]*|'')
            echo "ENTRY_ID contains unsupported characters." >&2
            return 2
            ;;
    esac
    final_id="$(proxy_entry_id "$entry_id" "$count")"
    if ((${#final_id} > 128)); then
        echo "Scaled Entry IDs must contain no more than 128 characters." >&2
        return 2
    fi
}

proxy_instance_port() {
    local instance="${1:?instance number is required}"
    printf '%s\n' "$((79 + 10#$instance))"
}

proxy_entry_id() {
    local base_id="${1:?base Entry ID is required}"
    local instance="${2:?instance number is required}"
    if [ "$instance" = 1 ]; then
        printf '%s\n' "$base_id"
    else
        printf '%s-%s\n' "$base_id" "$instance"
    fi
}

proxy_advertised_host() {
    local address="${1:?advertised address is required}"
    printf '%s\n' "${address%:*}"
}

proxy_advertised_address() {
    local base_address="${1:?advertised address is required}"
    local instance="${2:?instance number is required}"
    printf '%s:%s\n' \
        "$(proxy_advertised_host "$base_address")" \
        "$(proxy_instance_port "$instance")"
}
