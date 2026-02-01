#!/bin/bash
# Start Proxy (Linux)
# Assumes proxy binary and proxy.toml are in the same directory as this script.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR" || exit 1

if [ ! -f "./proxy" ]; then
    echo "Error: ./proxy binary not found in script directory."
    exit 1
fi

CONFIG_PATH="proxy.toml"
if [ ! -f "$CONFIG_PATH" ]; then
    echo "Warning: proxy.toml not found. Starting without --config (using defaults)."
    CONFIG_PATH=""
fi

# Create data directory for SQLite database
mkdir -p data
mkdir -p logs

# Migrate users from TOML to SQLite database if users.toml exists
USERS_TOML="users.toml"
if [ -f "$USERS_TOML" ] && [ -n "$CONFIG_PATH" ]; then
    echo "Migrating users from $USERS_TOML to database..."
    ./proxy --config "$CONFIG_PATH" --migrate-users "$USERS_TOML" 2>&1 | tee -a logs/migration.log
    echo "User migration completed."
fi

echo "Starting Proxy..."
if [ -n "$CONFIG_PATH" ]; then
    ./proxy --config "$CONFIG_PATH" > logs/proxy.out 2>&1
else
    ./proxy > logs/proxy.out 2>&1
fi
echo "Proxy started with PID $!"
