@echo off
REM PPAASS Desktop Agent UI Build Script for Windows

cd /d "%~dp0desktop-agent-ui"

REM Check if node is installed
where node >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo Error: Node.js is not installed. Please install Node.js 18+ first.
    exit /b 1
)

REM Install the exact dependency set from package-lock.json.
REM This also picks up newly added packages when node_modules already exists.
echo Installing dependencies...
call npm ci
if %ERRORLEVEL% NEQ 0 (
    echo Error: Failed to install dependencies.
    exit /b 1
)

REM Build Tauri application
echo Building PPAASS Desktop Agent UI...
call npm run tauri build
if %ERRORLEVEL% NEQ 0 (
    echo Error: Failed to build PPAASS Desktop Agent UI.
    exit /b 1
)

echo.
echo Build complete! The application bundle is in:
echo   desktop-agent-ui\src-tauri\target\release\bundle\
