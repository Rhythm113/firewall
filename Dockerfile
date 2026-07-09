# Stage 1: Build stage
FROM debian:bullseye-slim AS builder

# Install build-time dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    wget \
    libpcre3-dev \
    libssl-dev \
    libxml2-dev \
    libexpat1-dev \
    libnetfilter-queue-dev \
    libyara-dev \
    zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

# Set build directory for Apache
WORKDIR /usr/src/httpd

# Download and extract Apache httpd 2.4.26 from official archives
RUN wget -4 -nv --no-check-certificate http://archive.apache.org/dist/httpd/httpd-2.4.26.tar.gz \
    && tar -xzf httpd-2.4.26.tar.gz --strip-components=1 \
    && rm httpd-2.4.26.tar.gz

# Download and extract APR (Apache Portable Runtime) and APR-util into srclib
RUN mkdir -p srclib/apr srclib/apr-util \
    && wget -4 -nv --no-check-certificate http://archive.apache.org/dist/apr/apr-1.6.2.tar.gz \
    && tar -xzf apr-1.6.2.tar.gz -C srclib/apr --strip-components=1 \
    && rm apr-1.6.2.tar.gz \
    && wget -4 -nv --no-check-certificate http://archive.apache.org/dist/apr/apr-util-1.6.0.tar.gz \
    && tar -xzf apr-util-1.6.0.tar.gz -C srclib/apr-util --strip-components=1 \
    && rm apr-util-1.6.0.tar.gz

# Configure, build, and install Apache
RUN ./configure \
    --prefix=/usr/local/apache2 \
    --with-included-apr \
    --enable-so \
    --enable-ssl \
    --enable-mods-shared=reallyall \
    && make -j$(nproc) \
    && make install

# Compile fw_nfq and fw_agent
WORKDIR /usr/src/firewall
COPY kernel ./kernel
COPY agent ./agent
RUN make -C kernel fw_nfq
RUN make -C agent

# Stage 2: Runtime stage
FROM debian:bullseye-slim

# Install runtime libraries, iptables, gnupg, and python3 for CGI testing
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcre3 \
    libssl1.1 \
    libxml2 \
    libexpat1 \
    libnetfilter-queue1 \
    libyara4 \
    iptables \
    gnupg \
    python3 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy the compiled Apache installation from builder stage
COPY --from=builder /usr/local/apache2 /usr/local/apache2

# Copy firewall binaries
COPY --from=builder /usr/src/firewall/kernel/fw_nfq /usr/local/bin/fw_nfq
COPY --from=builder /usr/src/firewall/agent/fw_agent /usr/local/bin/fw_agent

# Copy custom landing page & vulnerable application
COPY index.html /usr/local/apache2/htdocs/
COPY vulnerable-app/upload.py /usr/local/apache2/cgi-bin/upload.py
RUN chmod +x /usr/local/apache2/cgi-bin/upload.py

# Copy entrypoint script
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# Set PATH environment variable
ENV PATH="/usr/local/apache2/bin:${PATH}"

# Forward Apache logs to stdout/stderr
RUN ln -sf /proc/self/fd/1 /usr/local/apache2/logs/access_log \
    && ln -sf /proc/self/fd/2 /usr/local/apache2/logs/error_log

# Create logs/signatures directories
RUN mkdir -p /var/log/firewall /etc/fw_inspect/yara \
    && touch /var/log/firewall/alerts.log

# Expose HTTP port 80
EXPOSE 80

WORKDIR /usr/local/apache2

# Set entrypoint
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
