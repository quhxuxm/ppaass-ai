#!/bin/bash
# Start Agent (macOS)
# Assumes agent binary and agent.toml are in the same directory as this script.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR" || exit 1

if [ ! -f "./agent" ]; then
    echo "Error: ./agent binary not found in script directory."
    exit 1
fi

CONFIG_PATH="agent.toml"
if [ ! -f "$CONFIG_PATH" ]; then
    echo "Warning: agent.toml not found. Starting without --config (using defaults)."
    CONFIG_PATH=""
fi

EXISTING_PIDS=$(pgrep -f "$SCRIPT_DIR/agent")
if [ -n "$EXISTING_PIDS" ]; then
    echo "Stopping existing Agent process(es): $EXISTING_PIDS"
    kill $EXISTING_PIDS 2>/dev/null || true
    sleep 2
    STILL_RUNNING=$(pgrep -f "$SCRIPT_DIR/agent")
    if [ -n "$STILL_RUNNING" ]; then
        echo "Force killing Agent process(es): $STILL_RUNNING"
        kill -9 $STILL_RUNNING 2>/dev/null || true
    fi
fi

echo "Starting Agent..."
mkdir -p logs
if [ -n "$CONFIG_PATH" ]; then
    nohup ./agent --config "$CONFIG_PATH"
else
    nohup ./agent
fi
echo "Agent started with PID $!"
