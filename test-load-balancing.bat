@echo off
setlocal enabledelayedexpansion

echo Testing load balancing...
echo.

for /L %%i in (1,1,10) do (
    echo Request %%i:
    curl -v -H "X-API-Key: zahariZDEwNWRlYTUtZjMzMy00MzE4LWJlN2QtZTIxYzYzZTFlODAy" http://localhost:9655/bulkemailchecker/instance-info
    echo.
    echo ----------------------------------------
    timeout /t 2 >nul
)

echo.
echo Checking Nginx status...
curl http://localhost:9655/nginx_status

echo.
echo Test completed! 