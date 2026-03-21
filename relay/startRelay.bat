@echo off
setlocal

taskkill /f /t /fi "windowtitle eq relay"
taskkill /f /t /fi "windowtitle eq relay - \"c:\\Users\\Bread\\Documents\\site block\\relay\\startRelay.bat\""

if not defined IS_MINIMIZED (
  set IS_MINIMIZED=1
  start "relay" /min "%~dpnx0" %*
  exit /b
)

cd /d "%~dp0"
uvicorn main:app --host 0.0.0.0 --port 8000
exit /b
