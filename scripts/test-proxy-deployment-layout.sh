#!/bin/sh
set -eu

require_text() {
    file="$1"
    text="$2"
    grep -F -- "$text" "$file" >/dev/null || {
        echo "$file is missing required deployment contract: $text" >&2
        exit 1
    }
}

reject_text() {
    file="$1"
    text="$2"
    if grep -Fi -- "$text" "$file" >/dev/null; then
        echo "$file still contains forbidden deployment coupling: $text" >&2
        exit 1
    fi
}

[ ! -e proxy-user-store ] || {
    echo "proxy-user-store must be merged into proxy-registry" >&2
    exit 1
}
[ ! -e .github/workflows/deploy-proxy-entry-and-registry.yml ] || {
    echo "the combined deployment workflow must not return" >&2
    exit 1
}
[ ! -e config/local ] || {
    echo "config/local must not return" >&2
    exit 1
}
[ ! -e config/remote ] || {
    echo "config/remote must not return" >&2
    exit 1
}
[ ! -e config/test ] || {
    echo "test-only configs must stay under tests/fixtures/config" >&2
    exit 1
}

require_text Cargo.toml '"proxy-control-protocol"'
require_text Cargo.toml '"proxy-registry"'
require_text proxy-entry/Cargo.toml 'proxy-control-protocol = { path = "../proxy-control-protocol" }'
reject_text proxy-entry/Cargo.toml 'proxy-registry'
reject_text proxy-entry/Cargo.toml 'sqlx'

require_text config/proxy-entry.toml 'registry_url = "https://'
reject_text config/proxy-entry.toml 'registry_control_url'
require_text config/proxy-entry.toml 'registry_control_token_path = '
require_text tests/fixtures/config/proxy-entry-integration.toml 'registry_url = "http://127.0.0.1:8797"'
require_text .github/workflows/deploy-proxy-entry.yml 'cp config/proxy-entry.toml "$bundle/proxy-entry.toml"'
require_text .github/workflows/deploy-proxy-entry.yml "printf 'REGISTRY_URL=%q"
require_text .github/workflows/deploy-proxy-entry.yml "printf 'ADVERTISED_ADDRESS=%q"
require_text .github/workflows/deploy-proxy-entry.yml "_ADVERTISED_ADDRESS', inputs.environment)"
reject_text .github/workflows/deploy-proxy-entry.yml 'REGISTRY_SCHEME'
require_text .github/workflows/deploy-proxy-entry.yml 'REGISTRY_URL: ${{ vars[format('
require_text .github/workflows/deploy-proxy-entry.yml "_REGISTRY_URL', inputs.environment)"
reject_text .github/workflows/deploy-proxy-entry.yml "_REGISTRY_HOST', inputs.environment)"
require_text .github/workflows/deploy-proxy-entry.yml "printf 'REGISTRY_URL=%q\\n' \"\$REGISTRY_URL\""
require_text .github/workflows/deploy-proxy-entry.yml 'bash deploy/proxy-entry/validate-registry-url.sh "$REGISTRY_URL"'
require_text .github/workflows/deploy-proxy-entry.yml 'install -m 0755 deploy/proxy-entry/validate-registry-url.sh'
reject_text .github/workflows/deploy-proxy-entry.yml "printf 'CONTROL_URL=%q"
reject_text .github/workflows/deploy-proxy-entry.yml 'control/v1/health'
require_text deploy/proxy-entry/install.sh ': "${REGISTRY_URL:?}"'
require_text deploy/proxy-entry/install.sh ': "${ADVERTISED_ADDRESS:?}"'
require_text deploy/proxy-entry/install.sh '"$bundle/validate-registry-url.sh" "$REGISTRY_URL"'
require_text deploy/proxy-entry/install.sh 'registry_url = \"$REGISTRY_URL\"'
require_text deploy/proxy-entry/install.sh 'advertised_address = \"$ADVERTISED_ADDRESS\"'
reject_text deploy/proxy-entry/install.sh '$CONTROL_URL'
reject_text deploy/proxy-entry/install.sh 'registry_control_url'
reject_text deploy/proxy-entry/install.sh 'sqlite'
reject_text deploy/proxy-entry/install.sh 'caddy'

require_text deploy/proxy-registry/install.sh 'write_registry_unit 1 8787 8797'
require_text deploy/proxy-registry/install.sh 'write_registry_unit 2 8788 8798'
require_text deploy/proxy-registry/install.sh 'lb_policy cookie ppaass_registry'
require_text deploy/proxy-registry/install.sh 'lb_policy random'
require_text deploy/proxy-registry/install.sh 'health_uri /healthz'
require_text deploy/proxy-registry/install.sh 'health_uri /control/v1/health'
require_text deploy/proxy-registry/install.sh 'ensure_caddy_service'
require_text deploy/proxy-registry/install.sh 'systemctl cat caddy.service'
require_text deploy/proxy-registry/install.sh 'cat >/etc/systemd/system/caddy.service'
require_text deploy/proxy-registry/install.sh 'cat >/etc/systemd/system/caddy.service.d/ppaass.conf'
require_text deploy/proxy-registry/install.sh 'User=caddy'
require_text deploy/proxy-registry/install.sh 'Environment=HOME=/var/lib/caddy'
require_text deploy/proxy-registry/install.sh 'ExecStart=$caddy_binary run --environ --config /etc/caddy/Caddyfile'
require_text deploy/proxy-registry/install.sh '"$caddy_binary" fmt --overwrite /etc/caddy/Caddyfile'
require_text deploy/proxy-registry/install.sh 'runuser -u caddy -- env HOME=/var/lib/caddy'
require_text deploy/proxy-registry/install.sh 'show_registry_service_diagnostics'
require_text deploy/proxy-registry/install.sh 'journalctl -u "$service" -n 100 --no-pager'
require_text deploy/proxy-registry/install.sh 'Registry instance $instance public API'
require_text deploy/proxy-registry/install.sh 'Registry instance $instance control API'
reject_text deploy/proxy-registry/install.sh 'curl --fail --silent --show-error --retry 20'
require_text deploy/proxy-registry/install.sh '@registry_control path /control /control/*'
require_text deploy/proxy-registry/install.sh 'handle @registry_control'
reject_text deploy/proxy-registry/install.sh 'handle_path /control'
reject_text deploy/proxy-registry/install.sh 'uri strip_prefix /control'
reject_text deploy/proxy-registry/install.sh 'CONTROL_HOST'
reject_text deploy/proxy-registry/install.sh '$PUBLIC_HOST'
require_text deploy/proxy-registry/install.sh '"https://$REGISTRY_HOST/control/v1/health"'
require_text deploy/proxy-registry/install.sh 'local tls_policy="${4:-verify}"'
require_text deploy/proxy-registry/install.sh 'insecure) curl_options+=(--insecure)'
require_text deploy/proxy-registry/install.sh '300 insecure'
external_insecure_checks="$(grep -Fc '    300 insecure' deploy/proxy-registry/install.sh)"
[ "$external_insecure_checks" -eq 2 ] || {
    echo "Both Registry external health checks must disable TLS verification." >&2
    exit 1
}
require_text deploy/proxy-registry/install.sh 'REGISTRY_PRODUCTION_KEY_ENCRYPTION_SECRET in the registry_production GitHub Environment'
reject_text deploy/proxy-entry/install.sh 'Waiting for the Registry control plane before starting Entry.'
reject_text deploy/proxy-entry/install.sh 'wait_for_http_health'
require_text deploy/proxy-entry/install.sh 'journalctl -u "$entry_service"'

awk '
    index($0, "Registry instance $instance public API") { public_wait = NR }
    index($0, "Registry instance $instance control API") { control_wait = NR }
    index($0, "systemctl reload-or-restart caddy.service") { caddy_reload = NR }
    END {
        if (!public_wait || !control_wait || !caddy_reload ||
            public_wait >= caddy_reload || control_wait >= caddy_reload) {
            exit 1
        }
    }
' deploy/proxy-registry/install.sh || {
    echo "Registry instances must become healthy before Caddy reloads" >&2
    exit 1
}

secret_path_assignments="$(
    grep -Fc 'SECRET_DIR="${PPAASS_PROXY_REGISTRY_SECRET_DIR:-.secrets}"' \
        start-proxy-registry.sh
)"
[ "$secret_path_assignments" -ge 2 ] || {
    echo "start-proxy-registry.sh must resolve secrets after loading runtime env" >&2
    exit 1
}
frontend_assignments="$(
    grep -Fc 'frontend="${PPAASS_PROXY_REGISTRY_FRONTEND_DIST:-proxy-registry-frontend}"' \
        start-proxy-registry.sh
)"
[ "$frontend_assignments" -ge 2 ] || {
    echo "start-proxy-registry.sh must validate the configured frontend path" >&2
    exit 1
}

for workflow in \
    .github/workflows/deploy-proxy-entry.yml \
    .github/workflows/deploy-proxy-registry.yml
do
    require_text "$workflow" "secrets[format('{0}_REMOTE_HOST', inputs.environment)]"
    require_text "$workflow" "secrets[format('{0}_REMOTE_USER', inputs.environment)]"
    require_text "$workflow" "secrets[format('{0}_REMOTE_PASSWORD', inputs.environment)]"
    require_text "$workflow" 'PubkeyAuthentication=no'
    require_text "$workflow" 'PreferredAuthentications=password'
    require_text "$workflow" 'StrictHostKeyChecking=accept-new'
    reject_text "$workflow" '_ENTRY_REMOTE_'
    reject_text "$workflow" '_REGISTRY_REMOTE_'
    reject_text "$workflow" 'PPAASS_DEPLOY_SSH_KNOWN_HOSTS'
    reject_text "$workflow" 'StrictHostKeyChecking=yes'
done

require_text .github/workflows/deploy-proxy-entry.yml "vars[format('{0}_ID', inputs.environment)]"
require_text .github/workflows/deploy-proxy-entry.yml "vars[format('{0}_REGISTRY_URL', inputs.environment)]"
reject_text .github/workflows/deploy-proxy-entry.yml "vars[format('{0}_CONTROL_PUBLIC_HOST', inputs.environment)]"
require_text .github/workflows/deploy-proxy-entry.yml "secrets[format('{0}_CONTROL_TOKEN', inputs.environment)]"
require_text .github/workflows/deploy-proxy-registry.yml "vars[format('{0}_REGISTRY_HOST', inputs.environment)]"
reject_text .github/workflows/deploy-proxy-registry.yml "vars[format('{0}_WEB_PUBLIC_HOST', inputs.environment)]"
reject_text .github/workflows/deploy-proxy-registry.yml "vars[format('{0}_CONTROL_PUBLIC_HOST', inputs.environment)]"
require_text .github/workflows/deploy-proxy-registry.yml "secrets[format('{0}_KEY_ENCRYPTION_SECRET', inputs.environment)]"
require_text .github/workflows/deploy-proxy-registry.yml "secrets[format('{0}_CONTROL_TOKEN', inputs.environment)]"
reject_text .github/workflows/deploy-proxy-entry.yml 'vars.PPAASS_'
reject_text .github/workflows/deploy-proxy-entry.yml 'secrets.PPAASS_'
reject_text .github/workflows/deploy-proxy-registry.yml 'vars.PPAASS_'
reject_text .github/workflows/deploy-proxy-registry.yml 'secrets.PPAASS_'
reject_text config/proxy-entry.toml 'registry-control.example.com'
reject_text proxy-registry/README.md 'registry-control.example.com'

require_text .github/workflows/deploy-proxy-entry.yml 'options: [entry_production]'
require_text .github/workflows/deploy-proxy-registry.yml 'options: [registry_production]'
require_text docs/GITHUB_ACTIONS_DEPLOYMENT.md 'ENTRY_PRODUCTION_REMOTE_HOST'
require_text docs/GITHUB_ACTIONS_DEPLOYMENT.md 'REGISTRY_PRODUCTION_REMOTE_HOST'

for registry_url in \
    'http://registry.example.com:80' \
    'https://registry.example.com:443' \
    'https://registry.example.com' \
    'https://127.0.0.1:8443' \
    'https://[2001:db8::1]:443'
do
    bash deploy/proxy-entry/validate-registry-url.sh "$registry_url"
done

for registry_url in \
    'registry.example.com' \
    'ftp://registry.example.com' \
    'https://' \
    'https://user@registry.example.com' \
    'https://registry.example.com/path' \
    'https://registry.example.com/' \
    'https://registry.example.com?query=yes' \
    'https://registry.example.com#fragment' \
    'https://user:password@registry.example.com' \
    'https://registry.example.com:0' \
    'https://registry.example.com:65536' \
    'https://registry.example.com:not-a-port' \
    'https://registry.example.com pipe' \
    'https://registry\\example.com' \
    'https://registry|example.com'
do
    if bash deploy/proxy-entry/validate-registry-url.sh "$registry_url" >/dev/null 2>&1; then
        echo "Invalid Registry URL was accepted: $registry_url" >&2
        exit 1
    fi
done

echo "Proxy Entry/Registry split deployment checks passed"
