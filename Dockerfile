FROM eclipse-temurin:21-jre-alpine

WORKDIR /app

# Add a dummy file that will change with each build 
# to ensure the JAR layer is not cached
ARG BUILD_DATE=Unknown
RUN echo $BUILD_DATE > build_date

# Add the application's jar to the container
COPY target/*.jar app.jar

# Set environment variables for JVM optimization in containers
ENV JAVA_TOOL_OPTIONS="-XX:+UseContainerSupport -XX:MaxRAMPercentage=75.0 -XX:+UseG1GC -XX:MaxGCPauseMillis=100 -XX:+UseStringDeduplication"

# Expose the API port - application.yml shows 8081
EXPOSE 8081

# Run the application
ENTRYPOINT ["java", "-jar", "/app/app.jar"] 