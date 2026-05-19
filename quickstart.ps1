# Quick Start Script for PPAASS
# This script helps you get started quickly

Write-Host @"
╔══════════════════════════════════════════════════════════════╗
║                    PPAASS Quick Start                        ║
║              Secure Proxy Application System                 ║
╚══════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

# Check if built
if (-not (Test-Path "target\release\proxy.exe")) {
    Write-Host "`n⚠️  Binaries not found. Building project..." -ForegroundColor Yellow
    .\build.ps1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "`n❌ Build failed. Please check the errors above." -ForegroundColor Red
        exit 1
    }
}

Write-Host "`n✅ Binaries found!" -ForegroundColor Green

# Create directories
Write-Host "`n📁 Setting up directories..." -ForegroundColor Cyan
New-Item -ItemType Directory -Force -Path "config", "keys" | Out-Null
Write-Host "   Created: config/, keys/" -ForegroundColor Gray

# Check configuration
if (-not (Test-Path "config\proxy.toml")) {
    Write-Host "`n⚠️  Proxy configuration not found. Please ensure config\proxy.toml exists." -ForegroundColor Yellow
} else {
    Write-Host "`n✅ Configuration files found!" -ForegroundColor Green
}

Write-Host @"

╔══════════════════════════════════════════════════════════════╗
║                     Next Steps                               ║
╚══════════════════════════════════════════════════════════════╝

1️⃣  Start the Proxy Server:
   .\target\release\proxy.exe --config config\proxy.toml

2️⃣  Add the user's public key to config\users.toml

3️⃣  Save the matching private key to keys\myuser.pem

4️⃣  Update config\agent.toml with your settings

5️⃣  Start the Agent:
   .\target\release\agent.exe --config config\agent.toml

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

Start Proxy:  .\target\release\proxy.exe --config config\proxy.toml
Start Agent:  .\target\release\agent.exe --config config\agent.toml

"@ -ForegroundColor White

Write-Host "🚀 Ready to start! Follow the steps above." -ForegroundColor Green
Write-Host ""
