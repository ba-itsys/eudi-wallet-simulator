FROM maven:3-eclipse-temurin-26 AS build
WORKDIR /build
COPY pom.xml .
COPY src ./src
RUN mvn -B package

FROM eclipse-temurin:25-jre
WORKDIR /app
COPY --from=build /build/target/wallet-simulator.jar .
EXPOSE 8080
CMD ["java", "-jar", "wallet-simulator.jar"]
