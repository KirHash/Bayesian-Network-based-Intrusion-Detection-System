@echo off
rem Double-click to start the server and open the dashboard.
rem Everything else (capture, retraining, settings, restart) is done in the dashboard.
rem Extra options go after the name, e.g.:  "Start Bayesian IDS.bat" --self-signed
cd /d "%~dp0"

rem open the browser a few seconds from now, once the server is up
start "" /b cmd /c "timeout /t 8 /nobreak >nul & start http://127.0.0.1:8000"

python serve.py %*

echo.
echo The server stopped. Press any key to close this window.
pause >nul
