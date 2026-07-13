@echo off
setlocal

call "%~dp0android-agent\build-release-apk-windows.bat" %*
set "EXIT_CODE=%ERRORLEVEL%"

endlocal & exit /b %EXIT_CODE%
