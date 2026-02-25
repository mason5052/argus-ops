# --- builder stage ---
FROM python:3.12-slim AS builder

WORKDIR /build

COPY pyproject.toml README.md ./
COPY src/ ./src/

# Install into a prefix so we can copy only the installed files
RUN pip install --no-cache-dir --prefix=/install ".[web,auth]"

# --- final stage ---
FROM python:3.12-slim

LABEL org.opencontainers.image.title="argus-ops" \
      org.opencontainers.image.description="AI-powered infrastructure monitoring CLI" \
      org.opencontainers.image.source="https://github.com/mason5052/argus-ops" \
      org.opencontainers.image.licenses="MIT"

WORKDIR /app

# Runtime system deps only
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Run as non-root
RUN useradd -m -u 1000 argus && \
    mkdir -p /home/argus/.argus-ops && \
    chown -R argus:argus /home/argus
USER argus

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -sf http://localhost:8080/api/status || exit 1

# 0.0.0.0 so it's accessible from outside the container
# --no-browser since there's no browser in a container
CMD ["argus-ops", "serve", "--host", "0.0.0.0", "--port", "8080", "--no-browser"]
