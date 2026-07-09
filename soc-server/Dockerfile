# Stage 1: Build Next.js Dashboard
FROM node:20-alpine AS next-builder
WORKDIR /usr/src/dashboard
COPY dashboard-next/package.json ./
RUN npm install
COPY dashboard-next/ ./
RUN npm run build

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
COPY soc_receiver.c db.c db.h auth.c auth.h pgp_wrapper.c pgp_wrapper.h protocol.h fw_inspect.h threat_intel.c threat_intel.h ./

# Compile receiver daemon
RUN make

# Stage 3: Runtime stage
FROM debian:bullseye-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    libssl1.1 \
    libcurl4 \
    libyara4 \
    ca-certificates \
    gnupg \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/local/bin

# Copy compiled receiver binary
COPY --from=builder /usr/src/soc/soc_receiver ./soc_receiver

# Copy statically compiled Next.js dashboard
COPY --from=next-builder /usr/src/dashboard/out /usr/local/share/soc/dashboard

# Copy keys and configs entrypoint
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

EXPOSE 1113
EXPOSE 8443

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
