@echo off
rem Puts the dashboard on the internet through a free Cloudflare tunnel.
rem Put your Netlify address in .env as IDS_SITE_URL=https://yoursite.netlify.app
cd /d "%~dp0"
python go_online.py
pause
