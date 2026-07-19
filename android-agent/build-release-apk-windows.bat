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

where rustup >nul 2>&1
if errorlevel 1 (
  echo Error: rustup was not found in PATH.
  exit /b 1
)

echo Ensuring Rust Android targets are installed...
rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
if errorlevel 1 (
  echo Error: failed to install the required Rust Android targets.
  exit /b 1
)

set "ZIPALIGN="
for /f "delims=" %%T in ('dir /b /s "%ANDROID_HOME%\build-tools\zipalign.exe" 2^>nul') do set "ZIPALIGN=%%T"
if not defined ZIPALIGN (
  for /f "delims=" %%T in ('dir /b /s "%ANDROID_HOME%\build-tools\*\zipalign.exe" 2^>nul') do set "ZIPALIGN=%%T"
)
if not defined ZIPALIGN (
  for /f "delims=" %%T in ('dir /b /s "%ANDROID_HOME%\build-tools\zipalign" 2^>nul') do set "ZIPALIGN=%%T"
)
if not defined ZIPALIGN (
  for /f "delims=" %%T in ('dir /b /s "%ANDROID_HOME%\build-tools\*\zipalign" 2^>nul') do set "ZIPALIGN=%%T"
)

if not defined ZIPALIGN (
  echo Error: Android build tool zipalign was not found under %ANDROID_HOME%\build-tools.
  exit /b 1
)

set "APKSIGNER="
for /f "delims=" %%T in ('dir /b /s "%ANDROID_HOME%\build-tools\apksigner.bat" 2^>nul') do set "APKSIGNER=%%T"
if not defined APKSIGNER (
  for /f "delims=" %%T in ('dir /b /s "%ANDROID_HOME%\build-tools\*\apksigner.bat" 2^>nul') do set "APKSIGNER=%%T"
)
if not defined APKSIGNER (
  for /f "delims=" %%T in ('dir /b /s "%ANDROID_HOME%\build-tools\apksigner.exe" 2^>nul') do set "APKSIGNER=%%T"
)
if not defined APKSIGNER (
  for /f "delims=" %%T in ('dir /b /s "%ANDROID_HOME%\build-tools\*\apksigner.exe" 2^>nul') do set "APKSIGNER=%%T"
)
if not defined APKSIGNER (
  for /f "delims=" %%T in ('dir /b /s "%ANDROID_HOME%\build-tools\apksigner" 2^>nul') do set "APKSIGNER=%%T"
)
if not defined APKSIGNER (
  for /f "delims=" %%T in ('dir /b /s "%ANDROID_HOME%\build-tools\*\apksigner" 2^>nul') do set "APKSIGNER=%%T"
)

if not defined APKSIGNER (
  echo Error: Android build tool apksigner was not found under %ANDROID_HOME%\build-tools.
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
  for /f "delims=" %%G in ('dir /b /s "%USERPROFILE%\.gradle\codex-dists\gradle.bat" 2^>nul') do (
    if not defined GRADLE_CMD set "GRADLE_CMD=%%G"
  )
)

if not defined GRADLE_CMD (
  for /f "delims=" %%G in ('dir /b /s "%USERPROFILE%\.gradle\wrapper\dists\gradle.bat" 2^>nul') do (
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

set "UNSIGNED_APK=app\build\outputs\apk\release\app-release-unsigned.apk"
set "ALIGNED_APK=app\build\outputs\apk\release\app-release-aligned.apk"
set "SIGNED_APK=app\build\outputs\apk\release\app-release-signed.apk"

if not exist "%UNSIGNED_APK%" (
  echo Error: unsigned release APK was not found at %UNSIGNED_APK%
  exit /b 1
)

set "KEYSTORE=%PPAASS_RELEASE_KEYSTORE%"
if not defined KEYSTORE set "KEYSTORE=%CD%\local-release.keystore"
set "KEY_ALIAS=%PPAASS_RELEASE_KEY_ALIAS%"
if not defined KEY_ALIAS set "KEY_ALIAS=ppaass-local-release"
set "STORE_PASSWORD=%PPAASS_RELEASE_STORE_PASSWORD%"
if not defined STORE_PASSWORD set "STORE_PASSWORD=ppaass-local-release"
set "KEY_PASSWORD=%PPAASS_RELEASE_KEY_PASSWORD%"
if not defined KEY_PASSWORD set "KEY_PASSWORD=%STORE_PASSWORD%"

set "KEYTOOL="
for /f "delims=" %%K in ('where keytool 2^>nul') do if not defined KEYTOOL set "KEYTOOL=%%K"
if not defined KEYTOOL if defined JAVA_HOME if exist "%JAVA_HOME%\bin\keytool.exe" set "KEYTOOL=%JAVA_HOME%\bin\keytool.exe"

if not exist "%KEYSTORE%" (
  if not defined KEYTOOL (
    echo Error: keytool was not found in PATH or JAVA_HOME\bin.
    exit /b 1
  )

  echo Creating local signing keystore: %KEYSTORE%
  "%KEYTOOL%" -genkeypair ^
    -keystore "%KEYSTORE%" ^
    -storepass "%STORE_PASSWORD%" ^
    -keypass "%KEY_PASSWORD%" ^
    -alias "%KEY_ALIAS%" ^
    -keyalg RSA ^
    -keysize 2048 ^
    -validity 10000 ^
    -dname "CN=PPAASS Local Release, OU=Development, O=PPAASS, L=Local, ST=Local, C=CN" >nul
  if errorlevel 1 exit /b 1
)

echo Signing release APK...
if exist "%ALIGNED_APK%" del /f /q "%ALIGNED_APK%"
if exist "%SIGNED_APK%" del /f /q "%SIGNED_APK%"
"%ZIPALIGN%" -f -p 4 "%UNSIGNED_APK%" "%ALIGNED_APK%"
if errorlevel 1 exit /b 1
call "%APKSIGNER%" sign ^
  --ks "%KEYSTORE%" ^
  --ks-key-alias "%KEY_ALIAS%" ^
  --ks-pass "pass:%STORE_PASSWORD%" ^
  --key-pass "pass:%KEY_PASSWORD%" ^
  --out "%SIGNED_APK%" ^
  "%ALIGNED_APK%"
if errorlevel 1 exit /b 1
call "%APKSIGNER%" verify --verbose "%SIGNED_APK%"
if errorlevel 1 exit /b 1
if exist "%ALIGNED_APK%" del /f /q "%ALIGNED_APK%"

echo.
echo Installable release APK:
echo %CD%\%SIGNED_APK%
echo.
echo All release APK output:
dir /b /s "app\build\outputs\apk\release\*.apk"

endlocal
