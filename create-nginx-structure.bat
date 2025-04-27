@echo off
setlocal

:: Create necessary directories
mkdir logs 2>nul
mkdir conf 2>nul
mkdir temp 2>nul

:: Copy nginx.conf to conf directory
copy nginx.conf conf\ 1>nul

echo Nginx directory structure created successfully! 