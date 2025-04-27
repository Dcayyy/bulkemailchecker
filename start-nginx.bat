@echo off
setlocal

:: Kill any existing Nginx processes
taskkill /F /IM nginx.exe

:: Start Nginx
start nginx -c %~dp0nginx.conf

echo Nginx started successfully! 