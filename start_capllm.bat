@echo off
setlocal
cd /d "%~dp0"

where python >nul 2>&1
if errorlevel 1 (
    echo Python was not found. Install Python and add it to PATH.
    pause
    exit /b 1
)

start "CapLLM Backend Demo" cmd /k "python run_demo.py"
start "CapLLM Frontend Dashboard" cmd /k "python -m http.server 8000 --directory dashboard"

timeout /t 2 /nobreak >nul
start "" "http://localhost:8000/index.html"

endlocal
