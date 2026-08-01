#!/bin/bash
set -euo pipefail

bundle="${1:?bundle directory is required}"
# shellcheck disable=SC1091
. "$bundle/deploy.env"

: "${RELEASE_SHA:?}"
: "${ENTRY_ID:?}"
: "${ADVERTISED_ADDRESS:?}"
: "${REGISTRY_URL:?}"
: "${RUNTIME_ROOT:=/opt/ppaass-entry}"

case "$RELEASE_SHA" in *[!0-9a-f]*|'') exit 2 ;; esac
case "$ENTRY_ID" in *[!0-9A-Za-z._:-]*|'') exit 2 ;; esac
"$bundle/validate-registry-url.sh" "$REGISTRY_URL"
case "$ADVERTISED_ADDRESS" in *[[:space:]/\\?#@]*|*://*|'') echo "Invalid ADVERTISED_ADDRESS" >&2; exit 2 ;; esac
case "$RUNTIME_ROOT" in /opt/*|/srv/*) ;; *) echo "Unsafe RUNTIME_ROOT" >&2; exit 2 ;; esac
if [ "$(id -u)" -ne 0 ]; then
    echo "Entry installation must run as root." >&2
    exit 1
fi
for command in find readlink sort stat systemctl; do
    command -v "$command" >/dev/null 2>&1 || {
        echo "$command is required on the Entry host." >&2
        exit 1
    }
done

service_user="ppaass-proxy-entry"
data_root="/var/lib/ppaass-entry"
secret_root="$data_root/secrets"
authorization_database="$data_root/authorization.sqlite3"
log_root="/var/log/ppaass/proxy-entry"
release_root="$RUNTIME_ROOT/releases/$RELEASE_SHA"
current_link="$RUNTIME_ROOT/current"
entry_service="ppaass-proxy-entry.service"

prune_old_releases() {
    local current_release
    local release_line
    local candidate
    local retained=0

    current_release="$(readlink -f "$current_link")"
    while IFS= read -r release_line; do
        retained=$((retained + 1))
        candidate="${release_line#* }"
        if [ "$retained" -gt 3 ] && [ "$candidate" != "$current_release" ]; then
            rm -rf -- "$candidate"
        fi
    done < <(find "$RUNTIME_ROOT/releases" -mindepth 1 -maxdepth 1 \
        -type d -printf '%T@ %p\n' | sort -nr)
}

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
if [ -L "$authorization_database" ]; then
    echo "Refusing symbolic-link authorization database: $authorization_database" >&2
    exit 1
fi
if [ -e "$authorization_database" ]; then
    if [ ! -f "$authorization_database" ]; then
        echo "Authorization database path is not a regular file: $authorization_database" >&2
        exit 1
    fi
    expected_uid="$(id -u "$service_user")"
    expected_gid="$(id -g "$service_user")"
    actual_uid="$(stat -c '%u' "$authorization_database")"
    actual_gid="$(stat -c '%g' "$authorization_database")"
    actual_mode="$(stat -c '%a' "$authorization_database")"
    if [ "$actual_uid" != "$expected_uid" ] || [ "$actual_gid" != "$expected_gid" ] || \
       [ "$actual_mode" != "600" ]; then
        echo "Authorization database must be owned by $service_user:$service_user with mode 0600." >&2
        exit 1
    fi
fi
install -m 0755 "$bundle/proxy-entry" "$release_root/proxy-entry"
install -o "$service_user" -g "$service_user" -m 0600 \
    "$bundle/control-token" "$secret_root/registry-control-token"

sed \
    -e "s|^entry_id = .*|entry_id = \"$ENTRY_ID\"|" \
    -e "s|^advertised_address = .*|advertised_address = \"$ADVERTISED_ADDRESS\"|" \
    -e "s|^registry_url = .*|registry_url = \"$REGISTRY_URL\"|" \
    -e "s|^registry_control_token_path = .*|registry_control_token_path = \"$secret_root/registry-control-token\"|" \
    -e "s|^authorization_database_path = .*|authorization_database_path = \"$authorization_database\"|" \
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
UMask=0077
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
prune_old_releases
echo "Entry $ENTRY_ID deployed at release $RELEASE_SHA."
