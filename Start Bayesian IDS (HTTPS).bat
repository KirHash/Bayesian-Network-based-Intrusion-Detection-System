@echo off
rem Starts the dashboard behind the Caddy reverse proxy and opens it over HTTPS.
rem   https://localhost:8443   the proxy (use this one)
rem   http://127.0.0.1:8000    the dashboard itself, still reachable on this machine
cd /d "%~dp0"

if not exist "proxy\bin\caddy.exe" (
    echo Installing Caddy ^(checks the download against the published checksum^)...
    powershell -NoProfile -ExecutionPolicy Bypass -File "proxy\install-caddy.ps1"
    if errorlevel 1 (
        echo Could not install Caddy.
        pause
        exit /b 1
    )
)

rem the proxy runs in its own minimized window; close that window to stop it
start "Bayesian IDS proxy" /min /d "proxy" "bin\caddy.exe" run --config Caddyfile --adapter caddyfile

rem open the browser a few seconds from now, once both are up
start "" /b cmd /c "timeout /t 10 /nobreak >nul & start https://localhost:8443"

python serve.py --behind-proxy %*

echo.
echo The dashboard stopped. Close the "Bayesian IDS proxy" window too if you are done.
pause >nul
