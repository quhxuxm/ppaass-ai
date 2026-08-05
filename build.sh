#!/bin/bash

echo "Building PPAASS project..."

# Build protocol first
echo -e "\nBuilding protocol..."
cargo build --release -p protocol
if [ $? -ne 0 ]; then
    echo "Failed to build protocol"
    exit 1
fi

# Build common
echo -e "\nBuilding common..."
cargo build --release -p common
if [ $? -ne 0 ]; then
    echo "Failed to build common"
    exit 1
fi

# Build desktop agent
echo -e "\nBuilding desktop-agent-be..."
cargo build --release -p desktop-agent-be
if [ $? -ne 0 ]; then
    echo "Failed to build desktop-agent-be"
    exit 1
fi

# Build Proxy Entry
echo -e "\nBuilding Proxy Entry..."
cargo build --release -p proxy-entry
if [ $? -ne 0 ]; then
    echo "Failed to build Proxy Entry"
    exit 1
fi

echo -e "\nBuild completed successfully!"
echo -e "\nExecutables location:"
echo "  Desktop Agent: target/release/desktop-agent"
echo "  Proxy Entry: target/release/proxy-entry"
