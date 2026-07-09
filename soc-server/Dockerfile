# Stage 1: Build stage
FROM debian:bullseye-slim AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libsqlite3-dev \
    libssl-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/soc

# Copy source files
COPY Makefile ./
COPY soc_receiver.c db.c db.h auth.c auth.h pgp_wrapper.c pgp_wrapper.h protocol.h fw_inspect.h ./

# Compile receiver daemon
RUN make

# Stage 2: Runtime stage
FROM debian:bullseye-slim

# Install runtime dependencies
# We install sqlite3, libssl1.1, ca-certificates, and gnupg (critical for PGP!)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libsqlite3-0 \
    libssl1.1 \
    ca-certificates \
    gnupg \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/local/bin

# Copy compiled receiver binary
COPY --from=builder /usr/src/soc/soc_receiver ./soc_receiver

# Copy dashboard static files
COPY dashboard /usr/local/share/soc/dashboard

# Expose agent port (1113) and dashboard port (8443)
EXPOSE 1113
EXPOSE 8443

# Copy entrypoint script
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# Run entrypoint
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
