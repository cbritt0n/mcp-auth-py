# Multi-stage build for production deployment
FROM python:3.11-slim AS builder

WORKDIR /build

# Install build dependencies
RUN pip install --upgrade pip setuptools wheel build

# Copy package files
COPY pyproject.toml README.md ./
COPY mcp_auth/ ./mcp_auth/

# Build the package
RUN python -m build --wheel --outdir /build/wheels

# Production image
FROM python:3.11-slim AS production

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

# Copy built wheel and install
COPY --from=builder /build/wheels/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/mcp_auth_py-*.whl[all] uvicorn[standard] \
    && rm -rf /tmp/*.whl

# Copy application
COPY examples/docker_app.py ./app.py

# Create non-root user
RUN useradd --create-home --shell /bin/bash app
USER app

# Configuration
ENV PYTHONUNBUFFERED=1
# Set runtime configuration via environment variables:
# docker run -e MCP_AUTH_PROVIDER=local -e MCP_AUTH_JWT_SECRET=your-secret-here

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:8000/health')"

# Expose port
EXPOSE 8000

# Run application
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]
