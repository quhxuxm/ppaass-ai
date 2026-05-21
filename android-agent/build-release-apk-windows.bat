@echo off
setlocal

REM Build the Android release APK on Windows.
REM Run this script from any directory; output goes to app\build\outputs\apk\release.

cd /d "%~dp0"

if not defined ANDROID_HOME (
  if exist "%LOCALAPPDATA%\Android\Sdk" (
    set "ANDROID_HOME=%LOCALAPPDATA%\Android\Sdk"
  )
)

if not defined ANDROID_HOME (
  echo Error: ANDROID_HOME is not set and %%LOCALAPPDATA%%\Android\Sdk was not found.
  exit /b 1
)

set "ANDROID_SDK_ROOT=%ANDROID_HOME%"

where cargo >nul 2>&1
if errorlevel 1 (
  echo Error: cargo was not found in PATH.
  exit /b 1
)

cargo ndk --version >nul 2>&1
if errorlevel 1 (
  echo Error: cargo-ndk was not found. Install it with: cargo install cargo-ndk
  exit /b 1
)

set "GRADLE_CMD="
if exist "gradlew.bat" (
  set "GRADLE_CMD=%CD%\gradlew.bat"
) else (
  for /f "delims=" %%G in ('where gradle 2^>nul') do (
    if not defined GRADLE_CMD set "GRADLE_CMD=%%G"
  )
)

if not defined GRADLE_CMD (
  for /f "usebackq delims=" %%G in (`powershell -NoProfile -ExecutionPolicy Bypass -Command "$root = Join-Path $env:USERPROFILE '.gradle\wrapper\dists'; $g = Get-ChildItem -Path $root -Recurse -Filter gradle.bat -ErrorAction SilentlyContinue | Sort-Object FullName -Descending | Select-Object -First 1 -ExpandProperty FullName; if ($g) { $g }"`) do (
    if not defined GRADLE_CMD set "GRADLE_CMD=%%G"
  )
)

if not defined GRADLE_CMD (
  echo Error: Gradle was not found. Install Gradle, add it to PATH, or add a Gradle wrapper.
  exit /b 1
)

echo Using Android SDK: %ANDROID_HOME%
echo Using Gradle: %GRADLE_CMD%
echo Building Android release APK...

call "%GRADLE_CMD%" assembleRelease
if errorlevel 1 exit /b 1

echo.
echo Release APK output:
dir /b /s "app\build\outputs\apk\release\*.apk"

endlocal
