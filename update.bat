@echo off
cd /d "%~dp0"
python tools\update.py --target 1500 --check
pause
