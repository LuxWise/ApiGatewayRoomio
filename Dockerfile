FROM maven:3.9.9-amazoncorretto-17 AS build
WORKDIR /app
COPY pom.xml .
RUN mvn dependency:go-offline
COPY src ./src
RUN mvn clean package -DskipTests

FROM amazoncorretto:17-alpine3.21-jdk
WORKDIR /app

RUN apk update && apk add --no-cache netcat-openbsd

COPY --from=build /app/target/*.jar app.jar
COPY wait-for-it.sh .
RUN chmod +x wait-for-it.sh

ENTRYPOINT ["sh", "./wait-for-it.sh", "rabbitmq:5672", "--", "java", "-jar", "app.jar"]
