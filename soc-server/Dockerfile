# Stage 1: Build Java Spring Boot Dashboard
FROM maven:3.8.5-openjdk-17-slim AS java-builder
WORKDIR /usr/src/dashboard
COPY dashboard-spring/pom.xml ./
# Pre-fetch dependencies to speed up subsequent builds
RUN mvn dependency:go-offline -B
COPY dashboard-spring/src ./src
RUN mvn package -DskipTests

# Stage 2: Build C SOC Server
FROM debian:bullseye-slim AS builder
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    libssl-dev \
    libcurl4-openssl-dev \
    libyara-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/soc
COPY Makefile ./
COPY soc_receiver.c db.c db.h auth.c auth.h aes_wrapper.c aes_wrapper.h protocol.h fw_inspect.h threat_intel.c threat_intel.h ./

# Compile receiver daemon
RUN make

# Stage 3: Runtime stage (uses Debian Bullseye and installs OpenJDK JRE)
FROM debian:bullseye-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    openjdk-17-jre-headless \
    libpq5 \
    libssl1.1 \
    libcurl4 \
    libyara4 \
    ca-certificates \
    gnupg \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/local/bin

# Copy compiled C receiver binary
COPY --from=builder /usr/src/soc/soc_receiver ./soc_receiver

# Copy Spring Boot packaged JAR file
COPY --from=java-builder /usr/src/dashboard/target/dashboard-1.0.0.jar ./dashboard.jar

# Copy keys and configs entrypoint
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

EXPOSE 1113
EXPOSE 8443

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
