#!/bin/bash
set -euo pipefail

bundle="${1:?bundle directory is required}"
# shellcheck disable=SC1091
. "$bundle/deploy.env"

: "${RELEASE_SHA:?}"
: "${ENTRY_ID:?}"
: "${REGISTRY_URL:?}"
: "${RUNTIME_ROOT:=/opt/ppaass-entry}"

case "$RELEASE_SHA" in *[!0-9a-f]*|'') exit 2 ;; esac
case "$ENTRY_ID" in *[!0-9A-Za-z._:-]*|'') exit 2 ;; esac
case "$REGISTRY_URL" in https://*) ;; *) echo "REGISTRY_URL must use HTTPS" >&2; exit 2 ;; esac
case "$RUNTIME_ROOT" in /opt/*|/srv/*) ;; *) echo "Unsafe RUNTIME_ROOT" >&2; exit 2 ;; esac
if [ "$(id -u)" -ne 0 ]; then
    echo "Entry installation must run as root." >&2
    exit 1
fi
for command in systemctl curl; do
    command -v "$command" >/dev/null 2>&1 || {
        echo "$command is required on the Entry host." >&2
        exit 1
    }
done

wait_for_http_health() {
    local label="$1"
    local url="$2"
    local timeout_seconds="$3"
    local retry_delay=5
    local deadline_epoch
    local attempt=0
    local status=000
    local response_file
    local error_file

    deadline_epoch="$(($(date +%s) + timeout_seconds))"
    response_file="$(mktemp)"
    error_file="$(mktemp)"
    while [ "$(date +%s)" -lt "$deadline_epoch" ]; do
        attempt=$((attempt + 1))
        : >"$response_file"
        : >"$error_file"
        status=000
        if status="$(
            curl --silent --show-error \
                --connect-timeout 5 --max-time 10 \
                --output "$response_file" \
                --write-out '%{http_code}' \
                "$url" 2>"$error_file"
        )" && [ "$status" = 200 ]; then
            rm -f "$response_file" "$error_file"
            echo "$label is ready."
            return 0
        fi
        if [ "$attempt" -eq 1 ] || [ $((attempt % 12)) -eq 0 ]; then
            echo "Waiting for $label at $url (last HTTP status: $status)." >&2
            if [ -s "$error_file" ]; then
                head -c 512 "$error_file" >&2
                echo >&2
            fi
        fi
        sleep "$retry_delay"
    done

    echo "$label did not become ready at $url (last HTTP status: $status)." >&2
    if [ -s "$error_file" ]; then
        head -c 2048 "$error_file" >&2
        echo >&2
    fi
    if [ -s "$response_file" ]; then
        echo "Last response body:" >&2
        head -c 2048 "$response_file" >&2
        echo >&2
    fi
    rm -f "$response_file" "$error_file"
    return 1
}

service_user="ppaass-proxy-entry"
data_root="/var/lib/ppaass-entry"
secret_root="$data_root/secrets"
log_root="/var/log/ppaass/proxy-entry"
release_root="$RUNTIME_ROOT/releases/$RELEASE_SHA"
current_link="$RUNTIME_ROOT/current"
entry_service="ppaass-proxy-entry.service"

if ! getent group "$service_user" >/dev/null; then
    groupadd --system "$service_user"
fi
if ! id "$service_user" >/dev/null 2>&1; then
    useradd --system --gid "$service_user" --home-dir "$data_root" \
        --shell /usr/sbin/nologin "$service_user"
fi

install -d -m 0755 "$RUNTIME_ROOT" "$RUNTIME_ROOT/releases" "$release_root"
install -d -o "$service_user" -g "$service_user" -m 0750 \
    "$data_root" "$secret_root" "$log_root"
install -m 0755 "$bundle/proxy-entry" "$release_root/proxy-entry"
install -o "$service_user" -g "$service_user" -m 0600 \
    "$bundle/control-token" "$secret_root/registry-control-token"

sed \
    -e "s|^entry_id = .*|entry_id = \"$ENTRY_ID\"|" \
    -e "s|^registry_url = .*|registry_url = \"$REGISTRY_URL\"|" \
    -e "s|^registry_control_token_path = .*|registry_control_token_path = \"$secret_root/registry-control-token\"|" \
    "$bundle/proxy-entry.toml" >"$release_root/proxy-entry.toml"
chmod 0644 "$release_root/proxy-entry.toml"
ln -sfn "$release_root" "$current_link"

cat >/etc/systemd/system/ppaass-proxy-entry.service <<EOF
[Unit]
Description=PPAASS Proxy Entry data plane
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=$service_user
Group=$service_user
WorkingDirectory=$current_link
ExecStart=$current_link/proxy-entry --config $current_link/proxy-entry.toml --log-dir $log_root
Restart=always
RestartSec=2
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$data_root $log_root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable "$entry_service"
echo "Waiting for the Registry control plane before starting Entry."
wait_for_http_health \
    "Registry control plane" \
    "$REGISTRY_URL/control/v1/health" \
    600
if ! systemctl restart "$entry_service"; then
    systemctl status "$entry_service" --no-pager --full >&2 || true
    journalctl -u "$entry_service" -n 100 --no-pager >&2 || true
    exit 1
fi

stable_checks=0
for _ in $(seq 1 30); do
    if systemctl is-active --quiet "$entry_service"; then
        stable_checks=$((stable_checks + 1))
        [ "$stable_checks" -ge 5 ] && break
    else
        stable_checks=0
    fi
    sleep 1
done
if [ "$stable_checks" -lt 5 ]; then
    echo "Entry service did not remain active after deployment." >&2
    systemctl status "$entry_service" --no-pager --full >&2 || true
    journalctl -u "$entry_service" -n 100 --no-pager >&2 || true
    exit 1
fi
echo "Entry $ENTRY_ID deployed at release $RELEASE_SHA."
