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

require_text Cargo.toml '"proxy-control-protocol"'
require_text Cargo.toml '"proxy-registry"'
require_text proxy-entry/Cargo.toml 'proxy-control-protocol = { path = "../proxy-control-protocol" }'
reject_text proxy-entry/Cargo.toml 'proxy-registry'
reject_text proxy-entry/Cargo.toml 'sqlx'

require_text config/remote/proxy-entry.toml 'registry_control_url = "https://'
require_text config/remote/proxy-entry.toml 'registry_control_token_path = '
reject_text deploy/proxy-entry/install.sh 'sqlite'
reject_text deploy/proxy-entry/install.sh 'caddy'

require_text deploy/proxy-registry/install.sh 'write_registry_unit 1 8787 8797'
require_text deploy/proxy-registry/install.sh 'write_registry_unit 2 8788 8798'
require_text deploy/proxy-registry/install.sh 'lb_policy cookie ppaass_registry'
require_text deploy/proxy-registry/install.sh 'lb_policy random'
require_text deploy/proxy-registry/install.sh 'health_uri /healthz'
require_text deploy/proxy-registry/install.sh 'health_uri /control/v1/health'

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

echo "Proxy Entry/Registry split deployment checks passed"
