#!/bin/bash
# Start Agent (macOS)
# Assumes desktop-agent binary and agent.toml are in the same directory as this script.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR" || exit 1

if [ ! -f "./desktop-agent" ]; then
    echo "Error: ./desktop-agent binary not found in script directory."
    exit 1
fi

CONFIG_PATH="agent.toml"
if [ ! -f "$CONFIG_PATH" ]; then
    echo "Warning: agent.toml not found. Starting without --config (using defaults)."
    CONFIG_PATH=""
fi

config_needs_tun_helper() {
    [ "$(uname -s)" = "Darwin" ] || return 1
    [ -n "$CONFIG_PATH" ] || return 1
    awk '
        BEGIN { in_tun = 0; enabled = 0; macos_helper_enabled = 1 }
        /^[[:space:]]*\[/ {
            in_tun = ($0 ~ /^[[:space:]]*\[tun\][[:space:]]*($|#)/)
            next
        }
        in_tun {
            line = $0
            sub(/[[:space:]]*#.*/, "", line)
            if (line ~ /^[[:space:]]*enabled[[:space:]]*=[[:space:]]*true[[:space:]]*$/) enabled = 1
            if (line ~ /^[[:space:]]*macos_helper_enabled[[:space:]]*=[[:space:]]*false[[:space:]]*$/) macos_helper_enabled = 0
            if (line ~ /^[[:space:]]*helper_enabled[[:space:]]*=[[:space:]]*false[[:space:]]*$/) macos_helper_enabled = 0
        }
        END { exit !(enabled && macos_helper_enabled) }
    ' "$CONFIG_PATH"
}

install_tun_helper_unix() {
    local agent_binary="$1"
    local socket_path="$2"
    local install_path="$3"
    local allowed_uid="${TUN_HELPER_ALLOWED_UID:-$(id -u)}"

    echo "Installing desktop-agent TUN helper mode from $agent_binary to $install_path..."
    sudo mkdir -p "$(dirname "$install_path")" || return 1
    sudo install -m 0755 "$agent_binary" "$install_path" || return 1
    sudo rm -f /usr/local/libexec/ppaass-tun-helper

    case "$(uname -s)" in
        Darwin)
            local legacy_plist_path="/Library/LaunchDaemons/com.ppaass.ai.tun-helper.plist"
            local plist_id="com.ppaass.ai.desktop-agent.tun-helper"
            local plist_path="/Library/LaunchDaemons/${plist_id}.plist"
            local tmp_plist
            tmp_plist="$(mktemp)" || return 1
            sudo launchctl bootout system "$legacy_plist_path" >/dev/null 2>&1 || true
            sudo rm -f "$legacy_plist_path"
            cat >"$tmp_plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>${plist_id}</string>
  <key>ProgramArguments</key>
  <array>
    <string>${install_path}</string>
    <string>--tun-helper-service</string>
    <string>--tun-helper-socket</string>
    <string>${socket_path}</string>
    <string>--tun-helper-allowed-uid</string>
    <string>${allowed_uid}</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>/var/log/ppaass-desktop-agent-tun-helper.log</string>
  <key>StandardErrorPath</key>
  <string>/var/log/ppaass-desktop-agent-tun-helper.err.log</string>
</dict>
</plist>
EOF
            sudo install -m 0644 "$tmp_plist" "$plist_path" || {
                rm -f "$tmp_plist"
                return 1
            }
            rm -f "$tmp_plist"
            sudo launchctl bootout system "$plist_path" >/dev/null 2>&1 || true
            sudo launchctl bootstrap system "$plist_path" || return 1
            sudo launchctl enable "system/${plist_id}" || return 1
            sudo launchctl kickstart -k "system/${plist_id}" || return 1
            echo "Installed launchd service: $plist_id"
            ;;
        Linux)
            local service_name="ppaass-desktop-agent-tun-helper.service"
            local service_path="/etc/systemd/system/${service_name}"
            local tmp_service
            tmp_service="$(mktemp)" || return 1
            sudo systemctl disable --now ppaass-tun-helper.service >/dev/null 2>&1 || true
            sudo rm -f /etc/systemd/system/ppaass-tun-helper.service
            cat >"$tmp_service" <<EOF
[Unit]
Description=PPAASS desktop-agent privileged TUN helper mode
After=network-online.target

[Service]
Type=simple
ExecStart=${install_path} --tun-helper-service --tun-helper-socket ${socket_path} --tun-helper-allowed-uid ${allowed_uid}
Restart=on-failure
RestartSec=2s

[Install]
WantedBy=multi-user.target
EOF
            sudo install -m 0644 "$tmp_service" "$service_path" || {
                rm -f "$tmp_service"
                return 1
            }
            rm -f "$tmp_service"
            sudo systemctl daemon-reload || return 1
            sudo systemctl enable "$service_name" || return 1
            sudo systemctl restart "$service_name" || return 1
            echo "Installed systemd service: $service_name"
            ;;
        *)
            echo "Warning: unsupported OS for automatic TUN helper install: $(uname -s)"
            return 1
            ;;
    esac

    echo "TUN helper socket: $socket_path"
    echo "TUN helper allowed uid: $allowed_uid"
}

helper_installed_unix() {
    local install_path="$1"

    [ -x "$install_path" ] || return 1
    case "$(uname -s)" in
        Darwin)
            [ -f "/Library/LaunchDaemons/com.ppaass.ai.desktop-agent.tun-helper.plist" ]
            ;;
        Linux)
            [ -f "/etc/systemd/system/ppaass-desktop-agent-tun-helper.service" ]
            ;;
        *)
            return 1
            ;;
    esac
}

wait_tun_helper_socket() {
    local socket_path="$1"
    local attempts=5
    local i=0

    while [ "$i" -lt "$attempts" ]; do
        [ -S "$socket_path" ] && return 0
        sleep 1
        i=$((i + 1))
    done

    return 1
}

ensure_tun_helper() {
    config_needs_tun_helper || return 0
    TUN_HELPER_REQUESTED=1

    local socket_path="${TUN_HELPER_SOCKET:-/var/run/ppaass-ai/tun-helper.sock}"
    local install_path="${TUN_HELPER_INSTALL_PATH:-/usr/local/libexec/ppaass-desktop-agent}"
    local agent_binary="${AGENT_BINARY:-$SCRIPT_DIR/desktop-agent}"

    if [ ! -x "$agent_binary" ]; then
        echo "Warning: TUN helper is enabled but no desktop-agent binary was found."
        echo "         Expected: $agent_binary"
        echo "         Agent will continue without falling back to sudo/UAC."
        return 0
    fi

    if helper_installed_unix "$install_path"; then
        if ! cmp -s "$agent_binary" "$install_path"; then
            echo "TUN helper service is installed but desktop-agent changed; updating helper mode..."
            if ! install_tun_helper_unix "$agent_binary" "$socket_path" "$install_path"; then
                echo "Warning: automatic TUN helper update failed."
                echo "         Agent will continue without falling back to sudo/UAC."
                return 0
            fi
        fi
        if [ ! -S "$socket_path" ]; then
            echo "TUN helper service is already installed; waiting for socket..."
            if ! wait_tun_helper_socket "$socket_path"; then
                echo "Warning: TUN helper socket is still unavailable: $socket_path"
                echo "         Not reinstalling, so this start will not prompt for sudo again."
                echo "         Check the helper service logs if TUN mode fails to start."
            fi
        fi
        return 0
    fi

    echo "TUN helper socket is not available; installing desktop-agent helper mode..."
    if ! install_tun_helper_unix "$agent_binary" "$socket_path" "$install_path"; then
        echo "Warning: automatic TUN helper install failed."
        echo "         Agent will continue without falling back to sudo/UAC."
        return 0
    fi

    if ! wait_tun_helper_socket "$socket_path"; then
        echo "Warning: TUN helper service was installed but socket is not available yet: $socket_path"
    fi
}

ensure_tun_helper

echo "Starting Agent..."
mkdir -p logs
AGENT_ARGS=()
if [ -n "$CONFIG_PATH" ]; then
    AGENT_ARGS+=(--config "$CONFIG_PATH")
fi
if [ "${TUN_HELPER_REQUESTED:-0}" = "1" ]; then
    AGENT_ARGS+=(--tun-helper-no-fallback)
fi
./desktop-agent "${AGENT_ARGS[@]}"
echo "Agent started."
