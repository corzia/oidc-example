# Build stage
FROM maven:3.9-eclipse-temurin-21-alpine AS build
WORKDIR /app
COPY pom.xml .
COPY src ./src
RUN mvn clean package -DskipTests

# Run stage
FROM tomcat:10.1-jdk21-openssl-alpine
WORKDIR /usr/local/tomcat/webapps/
# Remove default apps
RUN rm -rf ROOT examples docs host-manager manager
# Copy war from build stage and rename to ROOT.war to serve at /
COPY --from=build /app/target/oidc-example.war ./ROOT.war

EXPOSE 8080
CMD ["catalina.sh", "run"]
