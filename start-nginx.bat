@echo off
setlocal

:: Kill any existing Nginx processes
taskkill /F /IM nginx.exe 2>nul

:: Start Nginx with the correct configuration path
start nginx -p %~dp0 -c conf\nginx.conf

echo Nginx started successfully! 