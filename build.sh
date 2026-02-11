#!/bin/bash

echo "Building PPAASS project..."

# tokio-console task instrumentation requires tokio_unstable at compile time.
export RUSTFLAGS="${RUSTFLAGS:+$RUSTFLAGS }--cfg tokio_unstable"

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

# Build agent
echo -e "\nBuilding agent..."
cargo build --release -p agent
if [ $? -ne 0 ]; then
    echo "Failed to build agent"
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
echo "  Agent: target/release/agent"
echo "  Proxy: target/release/proxy"
