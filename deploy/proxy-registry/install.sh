#!/bin/bash
set -euo pipefail

bundle="${1:?bundle directory is required}"
# shellcheck disable=SC1091
. "$bundle/deploy.env"

: "${RELEASE_SHA:?}"
: "${PUBLIC_HOST:?}"
: "${CONTROL_HOST:?}"
: "${RUNTIME_ROOT:=/opt/ppaass-registry}"

case "$RELEASE_SHA" in *[!0-9a-f]*|'') exit 2 ;; esac
case "$PUBLIC_HOST$CONTROL_HOST" in *[!0-9A-Za-z._-]*) exit 2 ;; esac
case "$RUNTIME_ROOT" in /opt/*|/srv/*) ;; *) echo "Unsafe RUNTIME_ROOT" >&2; exit 2 ;; esac
if [ "$(id -u)" -ne 0 ]; then
    echo "Registry installation must run as root." >&2
    exit 1
fi
for command in systemctl openssl caddy curl; do
    command -v "$command" >/dev/null 2>&1 || {
        echo "$command is required on the Registry host." >&2
        exit 1
    }
done

service_user="ppaass-proxy-registry"
state_root="/var/lib/ppaass"
user_data_root="$state_root/users"
access_data_root="$state_root/access"
secret_root="$state_root/secrets"
identity_root="$state_root/identity"
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
install -d -m 0755 "$identity_root"
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
identity_public="$identity_root/proxy-identity-public.pem"
if [ -f "$identity_public" ]; then
    existing_der="$(mktemp)"
    supplied_der="$(mktemp)"
    openssl pkey -pubin -in "$identity_public" -outform DER -out "$existing_der"
    openssl pkey -pubin -in "$bundle/proxy-identity-public.pem" \
        -outform DER -out "$supplied_der"
    cmp "$existing_der" "$supplied_der" || {
        rm -f "$existing_der" "$supplied_der"
        echo "The supplied Proxy identity does not match existing data." >&2
        exit 1
    }
    rm -f "$existing_der" "$supplied_der"
else
    install -o "$service_user" -g "$service_user" -m 0640 \
        "$bundle/proxy-identity-public.pem" "$identity_public"
fi
chown "$service_user:$service_user" "$identity_public"
chmod 0640 "$identity_public"
openssl pkey -pubin -in "$identity_public" \
    -noout >/dev/null

cat >"$release_root/proxy-registry.env" <<EOF
PPAASS_PROXY_REGISTRY_BOOTSTRAP_ADMIN_USERNAME=admin
PPAASS_PROXY_REGISTRY_ALLOW_REGISTRATION=true
PPAASS_PROXY_REGISTRY_PUBLIC_HOST=$PUBLIC_HOST
PPAASS_PROXY_REGISTRY_SECURE_COOKIES=true
PPAASS_PROXY_REGISTRY_TRUST_PROXY_HEADERS=true
PPAASS_PROXY_REGISTRY_DATABASE=$user_data_root/proxy-users.sqlite3
PPAASS_PROXY_REGISTRY_ACCESS_LOG_DATABASE=$access_data_root/proxy-access.sqlite3
PPAASS_PROXY_REGISTRY_PROXY_IDENTITY_PUBLIC_KEY=$identity_public
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
$PUBLIC_HOST {
    encode zstd gzip
    reverse_proxy 127.0.0.1:8787 127.0.0.1:8788 {
        lb_policy cookie ppaass_registry
        health_uri /healthz
        lb_try_duration 5s
    }
}

$CONTROL_HOST {
    reverse_proxy 127.0.0.1:8797 127.0.0.1:8798 {
        lb_policy random
        health_uri /control/v1/health
        lb_try_duration 5s
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
    curl --fail --silent --retry 20 --retry-delay 1 \
        "http://127.0.0.1:$port/healthz" >/dev/null
done
for port in 8797 8798; do
    curl --fail --silent --retry 20 --retry-delay 1 \
        "http://127.0.0.1:$port/control/v1/health" >/dev/null
done
curl --fail --silent --retry 10 --retry-delay 2 \
    "https://$PUBLIC_HOST/healthz" >/dev/null
echo "Registry $RELEASE_SHA deployed with two instances."
