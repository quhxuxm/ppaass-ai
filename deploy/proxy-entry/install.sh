#!/bin/bash
set -euo pipefail

bundle="${1:?bundle directory is required}"
# shellcheck disable=SC1091
. "$bundle/deploy.env"
# shellcheck disable=SC1091
. "$bundle/instance-layout.sh"
# shellcheck disable=SC1091
. "$bundle/configure-firewall.sh"
# shellcheck disable=SC1091
. "$bundle/check-ports.sh"

: "${RELEASE_SHA:?}"
: "${ENTRY_ID:?}"
: "${ADVERTISED_ADDRESS:?}"
: "${REGISTRY_URL:?}"
: "${INSTANCE_COUNT:=1}"
: "${RUNTIME_ROOT:=/opt/ppaass-entry}"

case "$RELEASE_SHA" in *[!0-9a-f]*|'') exit 2 ;; esac
validate_instance_count "$INSTANCE_COUNT"
validate_entry_id_for_instances "$ENTRY_ID" "$INSTANCE_COUNT"
"$bundle/validate-registry-url.sh" "$REGISTRY_URL"
validate_advertised_address "$ADVERTISED_ADDRESS"
case "$RUNTIME_ROOT" in /opt/*|/srv/*) ;; *) echo "Unsafe RUNTIME_ROOT" >&2; exit 2 ;; esac
if [ "$(id -u)" -ne 0 ]; then
    echo "Entry installation must run as root." >&2
    exit 1
fi
for command in find readlink sort ss stat systemctl; do
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
entry_service_template="ppaass-proxy-entry@.service"
instance_count_file="$data_root/instance-count"

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

validate_authorization_database() {
    local database="$1"
    local expected_uid
    local expected_gid
    local actual_uid
    local actual_gid
    local actual_mode

    if [ -L "$database" ]; then
        echo "Refusing symbolic-link authorization database: $database" >&2
        exit 1
    fi
    [ -e "$database" ] || return 0
    if [ ! -f "$database" ]; then
        echo "Authorization database path is not a regular file: $database" >&2
        exit 1
    fi
    expected_uid="$(id -u "$service_user")"
    expected_gid="$(id -g "$service_user")"
    actual_uid="$(stat -c '%u' "$database")"
    actual_gid="$(stat -c '%g' "$database")"
    actual_mode="$(stat -c '%a' "$database")"
    if [ "$actual_uid" != "$expected_uid" ] || [ "$actual_gid" != "$expected_gid" ] || \
       [ "$actual_mode" != "600" ]; then
        echo "Authorization database must be owned by $service_user:$service_user with mode 0600: $database" >&2
        exit 1
    fi
}

show_entry_diagnostics() {
    local instance
    local service
    for instance in $(seq 1 "$INSTANCE_COUNT"); do
        service="ppaass-proxy-entry@$instance.service"
        systemctl status "$service" --no-pager --full >&2 || true
        journalctl -u "$service" -n 100 --no-pager >&2 || true
    done
}

mapfile -t current_entry_pids < <(managed_entry_pids)
if ! check_entry_ports_available "$INSTANCE_COUNT" "${current_entry_pids[@]}"; then
    echo "Deployment stopped before changing the running Proxy Entry services." >&2
    exit 1
fi

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

for instance in $(seq 1 "$INSTANCE_COUNT"); do
    instance_port="$(proxy_instance_port "$instance")"
    instance_id="$(proxy_entry_id "$ENTRY_ID" "$instance")"
    instance_address="$(proxy_advertised_address "$ADVERTISED_ADDRESS" "$instance")"
    if [ "$instance" = 1 ]; then
        authorization_database="$data_root/authorization.sqlite3"
    else
        authorization_database="$data_root/authorization-$instance.sqlite3"
    fi
    instance_release="$release_root/instances/$instance"
    validate_authorization_database "$authorization_database"
    install -d -m 0755 "$instance_release"
    install -d -o "$service_user" -g "$service_user" -m 0750 "$log_root/$instance"
    sed \
        -e "s|^listen_addr = .*|listen_addr = \"0.0.0.0:$instance_port\"|" \
        -e "s|^entry_id = .*|entry_id = \"$instance_id\"|" \
        -e "s|^advertised_address = .*|advertised_address = \"$instance_address\"|" \
        -e "s|^registry_url = .*|registry_url = \"$REGISTRY_URL\"|" \
        -e "s|^registry_control_token_path = .*|registry_control_token_path = \"$secret_root/registry-control-token\"|" \
        -e "s|^authorization_database_path = .*|authorization_database_path = \"$authorization_database\"|" \
        "$bundle/proxy-entry.toml" >"$instance_release/proxy-entry.toml"
    chmod 0644 "$instance_release/proxy-entry.toml"
done
ln -sfn "$release_root" "$current_link"

cat >/etc/systemd/system/$entry_service_template <<EOF
[Unit]
Description=PPAASS Proxy Entry data plane instance %i
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=$service_user
Group=$service_user
UMask=0077
WorkingDirectory=$current_link
ExecStart=$current_link/proxy-entry --config $current_link/instances/%i/proxy-entry.toml --log-dir $log_root/%i
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

if [ -e /etc/systemd/system/ppaass-proxy-entry.service ]; then
    systemctl disable --now ppaass-proxy-entry.service >/dev/null 2>&1 || true
    rm -f -- /etc/systemd/system/ppaass-proxy-entry.service
fi
systemctl daemon-reload
previous_count=0
if [ -f "$instance_count_file" ]; then
    read -r previous_count <"$instance_count_file"
    [[ "$previous_count" =~ ^[0-9]+$ ]] || previous_count=0
fi
if ((previous_count > INSTANCE_COUNT)); then
    for instance in $(seq "$((INSTANCE_COUNT + 1))" "$previous_count"); do
        systemctl disable --now "ppaass-proxy-entry@$instance.service" || true
    done
fi

configure_entry_firewall "$INSTANCE_COUNT"
for instance in $(seq 1 "$INSTANCE_COUNT"); do
    entry_service="ppaass-proxy-entry@$instance.service"
    systemctl enable "$entry_service"
    if ! systemctl restart "$entry_service"; then
        show_entry_diagnostics
        exit 1
    fi
done

stable_checks=0
for _ in $(seq 1 30); do
    all_active=1
    for instance in $(seq 1 "$INSTANCE_COUNT"); do
        if ! systemctl is-active --quiet "ppaass-proxy-entry@$instance.service"; then
            all_active=0
        fi
    done
    if [ "$all_active" = 1 ]; then
        stable_checks=$((stable_checks + 1))
        [ "$stable_checks" -ge 5 ] && break
    else
        stable_checks=0
    fi
    sleep 1
done
if [ "$stable_checks" -lt 5 ]; then
    echo "One or more Entry services did not remain active after deployment." >&2
    show_entry_diagnostics
    exit 1
fi
printf '%s\n' "$INSTANCE_COUNT" >"$instance_count_file"
prune_old_releases
echo "Entry $ENTRY_ID deployed with $INSTANCE_COUNT instance(s) at release $RELEASE_SHA."
echo "TCP and UDP ports: $(entry_port_list "$INSTANCE_COUNT")"
