FROM maven:3.9-eclipse-temurin-11
WORKDIR /app
COPY pom.xml .
COPY src/ src/
RUN mvn package -B -q -DskipTests
