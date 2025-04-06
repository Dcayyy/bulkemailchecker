@echo off
echo ===== REBUILDING WITH LATEST CODE =====

echo 1. Building the latest JAR with Maven...
call mvnw.cmd clean package -DskipTests

echo 2. Stopping current container...
docker stop bulk-email-checker || echo No container to stop

echo 3. Removing current container...
docker rm bulk-email-checker || echo No container to remove

echo 4. Rebuilding Docker image with current timestamp...
for /f "tokens=2 delims==" %%I in ('wmic os get localdatetime /format:list') do set datetime=%%I
set BUILD_DATE=%datetime%
docker-compose build --no-cache --build-arg BUILD_DATE=%BUILD_DATE%

echo 5. Starting new container with the latest JAR...
docker-compose up -d

echo ===== COMPLETED =====
echo Container is now running with the latest changes
echo To check logs: docker logs -f bulk-email-checker 