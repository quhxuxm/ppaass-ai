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
echo -e "\nBuilding desktop-agent..."
cargo build --release -p desktop-agent
if [ $? -ne 0 ]; then
    echo "Failed to build desktop-agent"
    exit 1
fi

# Build proxy
echo -e "\nBuilding proxy..."
cargo build --release -p proxy
if [ $? -ne 0 ]; then
    echo "Failed to build proxy"
    exit 1
fi

echo -e "\nBuild completed successfully!"
echo -e "\nExecutables location:"
echo "  Desktop Agent: target/release/desktop-agent"
echo "  Proxy: target/release/proxy"
