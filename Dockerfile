FROM python:3.12-slim

WORKDIR /app

# Install system deps (kubectl not needed - uses in-cluster config)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy project files
COPY pyproject.toml README.md ./
COPY src/ ./src/

# Install argus-ops with web extras
RUN pip install --no-cache-dir -e ".[web]"

# Run as non-root
RUN useradd -m -u 1000 argus && chown -R argus:argus /app
USER argus

EXPOSE 8080

# 0.0.0.0 so it's accessible from outside the container
# --no-browser since there's no browser in container
CMD ["argus-ops", "serve", "--host", "0.0.0.0", "--port", "8080", "--no-browser"]
