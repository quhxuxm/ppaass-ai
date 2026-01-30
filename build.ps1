# Build all components
Write-Host "Building PPAASS project..." -ForegroundColor Green

# Build protocol first
Write-Host "`nBuilding protocol..." -ForegroundColor Cyan
cargo build --release -p protocol
if ($LASTEXITCODE -ne 0) {
    Write-Host "Failed to build protocol" -ForegroundColor Red
    exit 1
}

# Build common
Write-Host "`nBuilding common..." -ForegroundColor Cyan
cargo build --release -p common
if ($LASTEXITCODE -ne 0) {
    Write-Host "Failed to build common" -ForegroundColor Red
    exit 1
}

# Build agent
Write-Host "`nBuilding agent..." -ForegroundColor Cyan
cargo build --release -p agent
if ($LASTEXITCODE -ne 0) {
    Write-Host "Failed to build agent" -ForegroundColor Red
    exit 1
}

# Build proxy
Write-Host "`nBuilding proxy..." -ForegroundColor Cyan
cargo build --release -p proxy
if ($LASTEXITCODE -ne 0) {
    Write-Host "Failed to build proxy" -ForegroundColor Red
    exit 1
}

Write-Host "`nBuild completed successfully!" -ForegroundColor Green
Write-Host "`nExecutables location:" -ForegroundColor Yellow
Write-Host "  Agent: target\release\agent.exe" -ForegroundColor White
Write-Host "  Proxy: target\release\proxy.exe" -ForegroundColor White
