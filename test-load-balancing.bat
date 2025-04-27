@echo off
setlocal enabledelayedexpansion

echo Testing load balancing...
echo.

for /L %%i in (1,1,10) do (
    echo Request %%i:
    curl -v http://localhost/api/instance-info
    echo.
    echo ----------------------------------------
    timeout /t 2 >nul
)

echo.
echo Checking Nginx status...
curl http://localhost/nginx_status

echo.
echo Test completed! 