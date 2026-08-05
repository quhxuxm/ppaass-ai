#!/bin/bash
set -euo pipefail

registry_url="${1:-}"
case "$registry_url" in
    http://*) registry_authority="${registry_url#http://}" ;;
    https://*) registry_authority="${registry_url#https://}" ;;
    *)
        echo "Registry URL must start with http:// or https://." >&2
        exit 2
        ;;
esac

case "$registry_authority" in
    ''|*/*|*'?'*|*'#'*|*'@'*|*'|'*|*'"'*|*"'"*|*'\'*|*[[:space:]]*)
        echo "Registry URL must be an origin without credentials, path, query, or fragment." >&2
        exit 2
        ;;
esac

port=''
if [[ "$registry_authority" =~ ^([0-9A-Za-z._-]+)(:([0-9]{1,5}))?$ ]]; then
    host="${BASH_REMATCH[1]}"
    port="${BASH_REMATCH[3]}"
    case "$host" in .*|*.|*..*)
        echo "Registry URL contains an invalid host name." >&2
        exit 2
        ;;
    esac
elif [[ "$registry_authority" =~ ^\[([0-9A-Fa-f:.]+)\](:([0-9]{1,5}))?$ ]]; then
    port="${BASH_REMATCH[3]}"
else
    echo "Registry URL contains an invalid host or port." >&2
    exit 2
fi

if [ -n "$port" ] && ((10#$port < 1 || 10#$port > 65535)); then
    echo "Registry URL port must be between 1 and 65535." >&2
    exit 2
fi
