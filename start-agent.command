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

echo "Starting Agent..."
mkdir -p logs
if [ -n "$CONFIG_PATH" ]; then
    sudo ./desktop-agent --config "$CONFIG_PATH"
else
    sudo ./desktop-agent
fi
echo "Agent started."
