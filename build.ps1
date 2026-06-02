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

# Build desktop agent
Write-Host "`nBuilding desktop-agent-be..." -ForegroundColor Cyan
cargo build --release -p desktop-agent-be
if ($LASTEXITCODE -ne 0) {
    Write-Host "Failed to build desktop-agent-be" -ForegroundColor Red
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
Write-Host "  Desktop Agent: target\release\desktop-agent.exe" -ForegroundColor White
Write-Host "  Proxy: target\release\proxy.exe" -ForegroundColor White
