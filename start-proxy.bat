@echo off
setlocal
REM Start Proxy (Windows)
REM Assumes proxy.exe and proxy.toml are in the same directory as this script.


cd /d "%~dp0"

if not exist "proxy.exe" (
  echo Error: proxy.exe not found in script directory.
  exit /b 1
)

set "CONFIG_PATH=proxy.toml"

REM Create data directory for SQLite database
if not exist "data" mkdir "data"
if not exist "logs" mkdir "logs"

REM Migrate users from TOML to SQLite database if users.toml exists
set "USERS_TOML=users.toml"
if exist "%USERS_TOML%" (
  if exist "%CONFIG_PATH%" (
    echo Migrating users from %USERS_TOML% to database...
    "%~dp0proxy.exe" --config "%CONFIG_PATH%" --migrate-users "%USERS_TOML%" >> "%~dp0logs\migration.log" 2>&1
    echo User migration completed.
  )
)

echo Starting Proxy...

if defined CONFIG_PATH (
  "%~dp0proxy.exe" --config "%CONFIG_PATH%" > "%~dp0logs\proxy.out" 2>&1
) else (
  "%~dp0proxy.exe" > "%~dp0logs\proxy.out" 2>&1
)

endlocal
