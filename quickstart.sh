#!/bin/bash

cat << "EOF"
╔══════════════════════════════════════════════════════════════╗
║                    PPAASS Quick Start                        ║
║              Secure Proxy Application System                 ║
╚══════════════════════════════════════════════════════════════╝
EOF

# Check if built
if [ ! -f "target/release/proxy-entry" ]; then
    echo ""
    echo "⚠️  Binaries not found. Building project..."
    chmod +x build.sh
    ./build.sh
    if [ $? -ne 0 ]; then
        echo ""
        echo "❌ Build failed. Please check the errors above."
        exit 1
    fi
fi

echo ""
echo "✅ Binaries found!"

# Create directories
echo ""
echo "📁 Setting up directories..."
mkdir -p config keys
echo "   Created: config/, keys/"

# Check configuration
if [ ! -f "config/proxy-entry.toml" ]; then
    echo ""
    echo "⚠️  Proxy configuration not found. Please ensure config/proxy-entry.toml exists."
else
    echo ""
    echo "✅ Configuration files found!"
fi

cat << "EOF"

╔══════════════════════════════════════════════════════════════╗
║                     Next Steps                               ║
╚══════════════════════════════════════════════════════════════╝

1️⃣  Start Proxy Entry:
   ./target/release/proxy-entry --config config/proxy-entry.toml

2️⃣  Start Proxy Registry and register the user

3️⃣  Approve the user's key request and expiration in the admin console

4️⃣  Sign in from the Agent UI; it downloads the approved managed credential

5️⃣  Start the Agent:
   ./target/release/desktop-agent --config config/agent.toml

6️⃣  Test the connection:
   curl --socks5 127.0.0.1:1080 http://example.com

╔══════════════════════════════════════════════════════════════╗
║                    Documentation                             ║
╚══════════════════════════════════════════════════════════════╝

📖 README.md  - Comprehensive documentation
📖 SETUP.md   - Detailed setup guide
📖 SUMMARY.md - Project overview

╔══════════════════════════════════════════════════════════════╗
║                    Quick Commands                            ║
╚══════════════════════════════════════════════════════════════╝

Start Proxy Entry:  ./target/release/proxy-entry --config config/proxy-entry.toml
Start Agent:  ./target/release/desktop-agent --config config/agent.toml

EOF

echo "🚀 Ready to start! Follow the steps above."
echo ""
