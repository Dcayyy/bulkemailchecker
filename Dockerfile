# Build stage
FROM maven:3.9.6-eclipse-temurin-21-alpine AS build
WORKDIR /app
COPY pom.xml .
COPY src ./src
RUN mvn clean package -DskipTests

# Final stage
FROM eclipse-temurin:21-jre-alpine

# Install network debugging tools
RUN apk add --no-cache curl netcat-openbsd tcpdump

WORKDIR /app

# Add a dummy file that will change with each build 
# to ensure the JAR layer is not cached
ARG BUILD_DATE=Unknown
RUN echo $BUILD_DATE > build_date

# Copy the built JAR from the build stage
COPY --from=build /app/target/*.jar app.jar

# Set environment variables for JVM optimization in containers
ENV JAVA_TOOL_OPTIONS="-XX:+UseContainerSupport -XX:MaxRAMPercentage=75.0 -XX:+UseG1GC -XX:MaxGCPauseMillis=100 -XX:+UseStringDeduplication"
ENV SMTP_TIMEOUT_MS=10000
ENV SMTP_CONNECTION_TIMEOUT_MS=5000
ENV SMTP_RETRY_COUNT=3
ENV SMTP_RETRY_DELAY_MS=1000
ENV SMTP_MAX_CONCURRENT_CONNECTIONS=5
ENV SMTP_DOMAIN_THROTTLE_DELAY_MS=500

# Expose the API port - application.yml shows 8081
EXPOSE 8081

# Run the application
ENTRYPOINT ["java", "-jar", "/app/app.jar"] 