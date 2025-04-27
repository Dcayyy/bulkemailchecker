@echo off
setlocal

call create-nginx-structure.bat
call start-nginx.bat
call start-instances.bat

echo.
echo All components started successfully!
echo Application is available at: http://localhost
echo.
pause 