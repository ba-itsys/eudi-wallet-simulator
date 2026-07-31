FROM maven:3.9.16-eclipse-temurin-25 AS build
WORKDIR /build
COPY pom.xml .
COPY src ./src
RUN mvn -B package

FROM eclipse-temurin:25-jre
WORKDIR /app
COPY --from=build /build/target/wallet-simulator.jar .
EXPOSE 8080
CMD ["java", "-jar", "wallet-simulator.jar"]
