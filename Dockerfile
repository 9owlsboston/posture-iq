# SecPostureIQ — Container Image
#
# Multi-stage build for production deployment on Azure Container Apps.
# Includes GitHub CLI (required for Copilot SDK runtime).

# ── Stage 1: Build ─────────────────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy dependency files first (layer caching)
COPY pyproject.toml ./
COPY requirements.txt* ./

# Copy source for package resolution by setuptools
COPY src/ ./src/

# Install Python dependencies (non-editable for production)
# Pin transitive deps to patch known CVEs (CVE-2026-23949, CVE-2026-24049)
# Remove setuptools+pip after install — not needed at runtime and setuptools
# vendors vulnerable copies of jaraco.context/wheel that Trivy flags.
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir . \
    && pip install --no-cache-dir --force-reinstall --no-deps \
       "jaraco.context>=6.1.0" "wheel>=0.46.2" \
    && pip uninstall -y setuptools pip

# ── Stage 2: Runtime ───────────────────────────────────────
FROM python:3.11-slim AS runtime

# Build arguments for version tracking
ARG GIT_SHA=unknown
ARG BUILD_TIME=unknown

ENV GIT_SHA=${GIT_SHA}
ENV BUILD_TIME=${BUILD_TIME}
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# Install runtime dependencies: GitHub CLI (for Copilot SDK runtime) + curl (health checks)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg \
       | dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" \
       | tee /etc/apt/sources.list.d/github-cli.list > /dev/null \
    && apt-get update && apt-get install -y --no-install-recommends gh \
    && rm -rf /var/lib/apt/lists/*

# Clear base-image site-packages to avoid stale dist-info (e.g. wheel 0.45.1)
# then copy the patched set from the builder stage
RUN rm -rf /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy application code
COPY src/ ./src/

# Create non-root user for security
RUN useradd --create-home --shell /bin/bash secpostureiq
USER secpostureiq

# Health check — used by Container Apps for liveness probe
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Expose the API port
EXPOSE 8000

# Start the FastAPI server
# --proxy-headers: honour X-Forwarded-Proto/For from the Container Apps ingress
# --forwarded-allow-ips='*': trust any upstream proxy (ACA routes via internal LB)
CMD ["uvicorn", "src.api.app:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1", "--proxy-headers", "--forwarded-allow-ips", "*"]
