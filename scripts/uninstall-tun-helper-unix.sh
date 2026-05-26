#!/usr/bin/env bash
set -euo pipefail

INSTALL_PATH="${INSTALL_PATH:-/usr/local/libexec/ppaass-desktop-agent}"
LEGACY_INSTALL_PATH="/usr/local/libexec/ppaass-tun-helper"

case "$(uname -s)" in
  Darwin)
    PLIST_ID="com.ppaass.ai.desktop-agent.tun-helper"
    PLIST_PATH="/Library/LaunchDaemons/${PLIST_ID}.plist"
    LEGACY_PLIST_PATH="/Library/LaunchDaemons/com.ppaass.ai.tun-helper.plist"
    sudo launchctl bootout system "$PLIST_PATH" >/dev/null 2>&1 || true
    sudo launchctl bootout system "$LEGACY_PLIST_PATH" >/dev/null 2>&1 || true
    sudo rm -f "$PLIST_PATH"
    sudo rm -f "$LEGACY_PLIST_PATH"
    ;;
  Linux)
    sudo systemctl disable --now ppaass-desktop-agent-tun-helper.service >/dev/null 2>&1 || true
    sudo systemctl disable --now ppaass-tun-helper.service >/dev/null 2>&1 || true
    sudo rm -f /etc/systemd/system/ppaass-desktop-agent-tun-helper.service
    sudo rm -f /etc/systemd/system/ppaass-tun-helper.service
    sudo systemctl daemon-reload
    ;;
  *)
    echo "Unsupported OS: $(uname -s)" >&2
    exit 1
    ;;
esac

sudo rm -f "$INSTALL_PATH"
sudo rm -f "$LEGACY_INSTALL_PATH"
sudo rm -f /var/run/ppaass-ai/tun-helper.sock

echo "Uninstalled desktop-agent TUN helper mode"
