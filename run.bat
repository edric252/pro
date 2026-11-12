@echo off
cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" (
    echo The project environment is missing.
    echo Follow the setup steps in README.md first.
    pause
    exit /b 1
)

echo Starting AccessHub at http://127.0.0.1:5000
echo Leave this window open while you use the site.
echo.
".venv\Scripts\python.exe" -m flask --app app run --host 127.0.0.1 --port 5000
pause
