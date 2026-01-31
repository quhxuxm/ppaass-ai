#!/bin/bash

cat << "EOF"
╔══════════════════════════════════════════════════════════════╗
║                    PPAASS Quick Start                        ║
║              Secure Proxy Application System                 ║
╚══════════════════════════════════════════════════════════════╝
EOF

# Check if built
if [ ! -f "target/release/proxy" ]; then
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
if [ ! -f "config/proxy.toml" ]; then
    echo ""
    echo "⚠️  Proxy configuration not found. Please ensure config/proxy.toml exists."
else
    echo ""
    echo "✅ Configuration files found!"
fi

cat << "EOF"

╔══════════════════════════════════════════════════════════════╗
║                     Next Steps                               ║
╚══════════════════════════════════════════════════════════════╝

1️⃣  Start the Proxy Server:
   ./target/release/proxy --config config/proxy.toml

2️⃣  In another terminal, add a user via API:
   curl -X POST http://localhost:8081/api/users \
     -H "Content-Type: application/json" \
     -d '{"username": "myuser", "bandwidth_limit_mbps": 100}'

3️⃣  Save the private key to keys/myuser.pem

4️⃣  Update config/agent.toml with your settings

5️⃣  Start the Agent:
   ./target/release/agent --config config/agent.toml

6️⃣  Test the connection:
   curl --socks5 127.0.0.1:1080 http://example.com

╔══════════════════════════════════════════════════════════════╗
║                    Documentation                             ║
╚══════════════════════════════════════════════════════════════╝

📖 README.md  - Comprehensive documentation
📖 SETUP.md   - Detailed setup guide
📖 API.md     - REST API documentation
📖 SUMMARY.md - Project overview

╔══════════════════════════════════════════════════════════════╗
║                    Quick Commands                            ║
╚══════════════════════════════════════════════════════════════╝

Start Proxy:  ./target/release/proxy --config config/proxy.toml
Start Agent:  ./target/release/agent --config config/agent.toml
Check Health: curl http://localhost:8081/health
List Users:   curl http://localhost:8081/api/users

EOF

echo "🚀 Ready to start! Follow the steps above."
echo ""
