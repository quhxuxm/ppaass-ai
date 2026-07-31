#!/bin/bash
set -euo pipefail

bundle="${1:?bundle directory is required}"
# shellcheck disable=SC1091
. "$bundle/deploy.env"

: "${RELEASE_SHA:?}"
: "${ENTRY_ID:?}"
: "${CONTROL_URL:?}"
: "${RUNTIME_ROOT:=/opt/ppaass-entry}"

case "$RELEASE_SHA" in *[!0-9a-f]*|'') exit 2 ;; esac
case "$ENTRY_ID" in *[!0-9A-Za-z._:-]*|'') exit 2 ;; esac
case "$CONTROL_URL" in https://*) ;; *) echo "CONTROL_URL must use HTTPS" >&2; exit 2 ;; esac
case "$RUNTIME_ROOT" in /opt/*|/srv/*) ;; *) echo "Unsafe RUNTIME_ROOT" >&2; exit 2 ;; esac
if [ "$(id -u)" -ne 0 ]; then
    echo "Entry installation must run as root." >&2
    exit 1
fi
for command in systemctl openssl curl; do
    command -v "$command" >/dev/null 2>&1 || {
        echo "$command is required on the Entry host." >&2
        exit 1
    }
done

service_user="ppaass-proxy-entry"
data_root="/var/lib/ppaass-entry"
secret_root="$data_root/secrets"
log_root="/var/log/ppaass/proxy-entry"
release_root="$RUNTIME_ROOT/releases/$RELEASE_SHA"
current_link="$RUNTIME_ROOT/current"

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
install -o "$service_user" -g "$service_user" -m 0600 \
    "$bundle/proxy-identity-private.pem" \
    "$data_root/proxy-identity-private.pem"
openssl pkey -in "$data_root/proxy-identity-private.pem" -noout >/dev/null

sed \
    -e "s|^entry_id = .*|entry_id = \"$ENTRY_ID\"|" \
    -e "s|^registry_control_url = .*|registry_control_url = \"$CONTROL_URL\"|" \
    -e "s|^registry_control_token_path = .*|registry_control_token_path = \"$secret_root/registry-control-token\"|" \
    -e "s|^transport_identity_private_key_path = .*|transport_identity_private_key_path = \"$data_root/proxy-identity-private.pem\"|" \
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
systemctl enable ppaass-proxy-entry.service
systemctl restart ppaass-proxy-entry.service
for _ in $(seq 1 20); do
    systemctl is-active --quiet ppaass-proxy-entry.service && break
    sleep 1
done
systemctl is-active --quiet ppaass-proxy-entry.service
curl --fail --silent --retry 10 --retry-delay 2 \
    "$CONTROL_URL/control/v1/health" >/dev/null
echo "Entry $ENTRY_ID deployed at release $RELEASE_SHA."
