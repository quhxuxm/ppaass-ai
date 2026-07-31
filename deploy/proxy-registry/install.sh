#!/bin/bash
set -euo pipefail

bundle="${1:?bundle directory is required}"
# shellcheck disable=SC1091
. "$bundle/deploy.env"

: "${RELEASE_SHA:?}"
: "${REGISTRY_HOST:?}"
: "${RUNTIME_ROOT:=/opt/ppaass-registry}"

case "$RELEASE_SHA" in *[!0-9a-f]*|'') exit 2 ;; esac
case "$REGISTRY_HOST" in *[!0-9A-Za-z._-]*) exit 2 ;; esac
case "$RUNTIME_ROOT" in /opt/*|/srv/*) ;; *) echo "Unsafe RUNTIME_ROOT" >&2; exit 2 ;; esac
if [ "$(id -u)" -ne 0 ]; then
    echo "Registry installation must run as root." >&2
    exit 1
fi
for command in systemctl caddy curl; do
    command -v "$command" >/dev/null 2>&1 || {
        echo "$command is required on the Registry host." >&2
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

service_user="ppaass-proxy-registry"
state_root="/var/lib/ppaass"
user_data_root="$state_root/users"
access_data_root="$state_root/access"
secret_root="$state_root/secrets"
log_root="/var/log/ppaass/proxy-registry"
release_root="$RUNTIME_ROOT/releases/$RELEASE_SHA"
current_link="$RUNTIME_ROOT/current"

if ! getent group "$service_user" >/dev/null; then
    groupadd --system "$service_user"
fi
if ! id "$service_user" >/dev/null 2>&1; then
    useradd --system --gid "$service_user" --home-dir "$state_root" \
        --shell /usr/sbin/nologin "$service_user"
fi

install -d -m 0755 "$RUNTIME_ROOT" "$RUNTIME_ROOT/releases"
install -d -o "$service_user" -g "$service_user" -m 0750 \
    "$user_data_root" "$access_data_root" "$secret_root" "$log_root"
install -d -m 0755 "$release_root" "$release_root/frontend"
install -m 0755 "$bundle/proxy-registry" "$release_root/proxy-registry"
install -m 0755 "$bundle/start-proxy-registry.sh" \
    "$release_root/start-proxy-registry.sh"
cp -a "$bundle/frontend/." "$release_root/frontend/"
find "$release_root/frontend" -type d -exec chmod 0755 {} +
find "$release_root/frontend" -type f -exec chmod 0644 {} +

key_secret="$secret_root/proxy-registry-key-encryption-secret"
legacy_key_secret="$secret_root/proxy-web-key-encryption-secret"
if [ ! -f "$key_secret" ] && [ -f "$legacy_key_secret" ]; then
    install -o "$service_user" -g "$service_user" -m 0600 \
        "$legacy_key_secret" "$key_secret"
fi
if [ -f "$key_secret" ]; then
    cmp "$bundle/registry-key-secret" "$key_secret" || {
        echo "The supplied Registry key secret does not match existing data." >&2
        echo "Refusing to replace the stable key at $key_secret." >&2
        echo "Set REGISTRY_PRODUCTION_KEY_ENCRYPTION_SECRET in the registry_production GitHub Environment to the original value." >&2
        exit 1
    }
else
    install -o "$service_user" -g "$service_user" -m 0600 \
        "$bundle/registry-key-secret" "$key_secret"
fi
chown "$service_user:$service_user" "$key_secret"
chmod 0600 "$key_secret"
install -o "$service_user" -g "$service_user" -m 0600 \
    "$bundle/control-token" \
    "$secret_root/proxy-registry-control-token"
install -o "$service_user" -g "$service_user" -m 0600 \
    "$bundle/admin-password" \
    "$secret_root/proxy-registry-admin-password"
cat >"$release_root/proxy-registry.env" <<EOF
PPAASS_PROXY_REGISTRY_BOOTSTRAP_ADMIN_USERNAME=admin
PPAASS_PROXY_REGISTRY_ALLOW_REGISTRATION=true
PPAASS_PROXY_REGISTRY_PUBLIC_HOST=$REGISTRY_HOST
PPAASS_PROXY_REGISTRY_SECURE_COOKIES=true
PPAASS_PROXY_REGISTRY_TRUST_PROXY_HEADERS=true
PPAASS_PROXY_REGISTRY_DATABASE=$user_data_root/proxy-users.sqlite3
PPAASS_PROXY_REGISTRY_ACCESS_LOG_DATABASE=$access_data_root/proxy-access.sqlite3
PPAASS_PROXY_REGISTRY_FRONTEND_DIST=$current_link/frontend
PPAASS_PROXY_REGISTRY_SECRET_DIR=$secret_root
RUST_LOG=proxy_registry=info,tower_http=info
EOF
chmod 0644 "$release_root/proxy-registry.env"
ln -sfn "$release_root" "$current_link"

write_registry_unit() {
    local instance="$1"
    local public_port="$2"
    local control_port="$3"
    cat >"/etc/systemd/system/ppaass-proxy-registry-$instance.service" <<EOF
[Unit]
Description=PPAASS Proxy Registry instance $instance
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=$service_user
Group=$service_user
WorkingDirectory=$current_link
Environment=PPAASS_PROXY_REGISTRY_RUNTIME_ENV_FILE=$current_link/proxy-registry.env
Environment=PPAASS_PROXY_REGISTRY_INSTANCE_ID=registry-$instance
Environment=PPAASS_PROXY_REGISTRY_LISTEN_ADDR=127.0.0.1:$public_port
Environment=PPAASS_PROXY_REGISTRY_CONTROL_LISTEN_ADDR=127.0.0.1:$control_port
Environment=PPAASS_PROXY_REGISTRY_LOG_DIR=$log_root/instance-$instance
ExecStart=$current_link/start-proxy-registry.sh run
Restart=always
RestartSec=2
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$user_data_root $access_data_root $secret_root $log_root

[Install]
WantedBy=multi-user.target
EOF
}

write_registry_unit 1 8787 8797
write_registry_unit 2 8788 8798

install -d -m 0755 /etc/caddy
cat >/etc/caddy/Caddyfile <<EOF
$REGISTRY_HOST {
    @registry_control path /control /control/*

    handle @registry_control {
        reverse_proxy 127.0.0.1:8797 127.0.0.1:8798 {
            lb_policy random
            health_uri /control/v1/health
            lb_try_duration 5s
        }
    }

    handle {
        encode zstd gzip
        reverse_proxy 127.0.0.1:8787 127.0.0.1:8788 {
            lb_policy cookie ppaass_registry
            health_uri /healthz
            lb_try_duration 5s
        }
    }
}
EOF
caddy validate --config /etc/caddy/Caddyfile

systemctl daemon-reload
systemctl enable ppaass-proxy-registry-1.service \
    ppaass-proxy-registry-2.service caddy.service
systemctl restart ppaass-proxy-registry-1.service
systemctl restart ppaass-proxy-registry-2.service
systemctl reload-or-restart caddy.service

for port in 8787 8788; do
    curl --fail --silent --show-error --retry 20 --retry-delay 1 \
        "http://127.0.0.1:$port/healthz" >/dev/null
done
for port in 8797 8798; do
    curl --fail --silent --show-error --retry 20 --retry-delay 1 \
        "http://127.0.0.1:$port/control/v1/health" >/dev/null
done
wait_for_http_health \
    "Registry public API" \
    "https://$REGISTRY_HOST/healthz" \
    300
wait_for_http_health \
    "Registry control API" \
    "https://$REGISTRY_HOST/control/v1/health" \
    300
echo "Registry $RELEASE_SHA deployed with two instances."
