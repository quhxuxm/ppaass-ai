@echo off
REM PPAASS Agent UI Build Script for Windows

cd /d "%~dp0agent-ui"

REM Check if node is installed
where node >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo Error: Node.js is not installed. Please install Node.js 18+ first.
    exit /b 1
)

REM Check if dependencies are installed
if not exist "node_modules" (
    echo Installing dependencies...
    call npm install
)

REM Build Tauri application
echo Building PPAASS Agent UI...
call npm run tauri build

echo.
echo Build complete! The application bundle is in:
echo   agent-ui\src-tauri\target\release\bundle\
