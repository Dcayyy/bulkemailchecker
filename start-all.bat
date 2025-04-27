@echo off
setlocal

:: Check if Nginx is installed
where nginx >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo Nginx is not installed or not in PATH. Please install Nginx and add it to your PATH.
    echo You can download Nginx from: http://nginx.org/en/download.html
    exit /b 1
)

:: Start Nginx
call start-nginx.bat

:: Start application instances
call start-instances.bat

echo All components started successfully!
echo Application is available at: http://localhost 