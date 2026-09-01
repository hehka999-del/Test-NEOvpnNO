@echo off
setlocal
cd /d "%~dp0"

if "%PYTHON%"=="" set "PYTHON=python"
if "%TARGET%"=="" set "TARGET=1500"
if "%WORKERS%"=="" set "WORKERS=64"

where "%PYTHON%" >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python 3 was not found.
    echo Install Python 3 and ensure "python" is in PATH.
    pause
    exit /b 1
)

"%PYTHON%" tools\update.py --target "%TARGET%" --check --geoip --workers "%WORKERS%"
if errorlevel 1 (
    echo [ERROR] Update failed. Existing output was not intentionally replaced.
    pause
    exit /b 1
)

echo [OK] Neo VPN subscription updated.
echo [INFO] Output: output\neo_vpn.txt
pause
endlocal
