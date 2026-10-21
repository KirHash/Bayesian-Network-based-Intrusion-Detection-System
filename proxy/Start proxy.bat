@echo off
rem Starts the reverse proxy. Start the dashboard first:  python serve.py --behind-proxy
cd /d "%~dp0"

if not exist "bin\caddy.exe" (
    echo Caddy is not installed yet. Run install-caddy.ps1 first:
    echo     powershell -ExecutionPolicy Bypass -File install-caddy.ps1
    pause
    exit /b 1
)

echo Open https://localhost:8443  (the browser will warn about the local certificate until you trust it:  bin\caddy.exe trust)
"bin\caddy.exe" run --config Caddyfile --adapter caddyfile
pause
