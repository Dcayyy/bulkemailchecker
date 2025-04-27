@echo off
setlocal enabledelayedexpansion

:: Kill any existing Java processes for this application
taskkill /F /IM java.exe /FI "WINDOWTITLE eq BulkEmailChecker*"

:: Start instances on different ports
start "BulkEmailChecker-8081" java -jar target/BulkEmailChecker-0.0.1-SNAPSHOT.jar --server.port=8081
start "BulkEmailChecker-8082" java -jar target/BulkEmailChecker-0.0.1-SNAPSHOT.jar --server.port=8082
start "BulkEmailChecker-8083" java -jar target/BulkEmailChecker-0.0.1-SNAPSHOT.jar --server.port=8083

echo All instances started successfully! 