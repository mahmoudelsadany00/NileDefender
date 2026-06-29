# ============================================================
# NileDefender — Production Dockerfile (multi-stage build)
# ============================================================

# ---------- Stage 1: Build React frontend ----------
FROM node:20-slim AS frontend-builder

WORKDIR /build

# Install frontend dependencies first (cached unless package.json changes)
COPY frontend/package.json frontend/package-lock.json* ./
RUN npm ci --no-audit --no-fund 2>/dev/null || npm install --no-audit --no-fund

# Copy frontend source and build
COPY frontend/ ./
RUN npm run build


# ---------- (dalfox is downloaded as a prebuilt binary in Stage 2) ----------


# ---------- Stage 2: Python runtime ----------
FROM python:3.13-slim

WORKDIR /app

# Install system dependencies:
#   - WeasyPrint needs:  libpango, libcairo, libgdk-pixbuf, libffi
#   - Selenium needs:    firefox-esr, wget (for geckodriver)
#   - sqlmap:            sqlmap
#   - General:           gcc (some pip packages need compilation)
RUN apt-get update && apt-get install -y --no-install-recommends \
    # WeasyPrint runtime deps
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libcairo2 \
    libgdk-pixbuf-2.0-0 \
    libffi-dev \
    libglib2.0-0 \
    # Selenium / Firefox
    firefox-esr \
    wget \
    # SQLi scanner
    sqlmap \
    # Build tools for pip packages that compile C extensions
    gcc \
    # curl for downloading dalfox with retries
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install dalfox (XSS scanner) — prebuilt binary from GitHub
ARG DALFOX_VERSION=2.13.0
RUN ARCH=$(dpkg --print-architecture) \
    && if [ "$ARCH" = "arm64" ]; then DALFOX_ARCH="arm64"; else DALFOX_ARCH="amd64"; fi \
    && echo "Downloading dalfox v${DALFOX_VERSION} for linux-${DALFOX_ARCH}..." \
    && curl -fSL --retry 5 --retry-delay 3 --retry-connrefused \
       "https://github.com/hahwul/dalfox/releases/download/v${DALFOX_VERSION}/dalfox-linux-${DALFOX_ARCH}.tar.gz" \
       -o /tmp/dalfox.tar.gz \
    && tar -xzf /tmp/dalfox.tar.gz -C /tmp/ \
    && mv /tmp/dalfox-linux-${DALFOX_ARCH} /usr/local/bin/dalfox \
    && chmod +x /usr/local/bin/dalfox \
    && rm -rf /tmp/dalfox* \
    && dalfox version

# Install geckodriver for Selenium + Firefox (pinned for reproducibility)
ARG GECKO_VERSION=v0.35.0
RUN wget -q "https://github.com/mozilla/geckodriver/releases/download/${GECKO_VERSION}/geckodriver-${GECKO_VERSION}-linux64.tar.gz" \
    && tar -xzf geckodriver-*.tar.gz -C /usr/local/bin/ \
    && rm geckodriver-*.tar.gz \
    && chmod +x /usr/local/bin/geckodriver

# Install Python dependencies (cached unless requirements.txt changes)
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY . /app/

# Copy built frontend from Stage 1
COPY --from=frontend-builder /build/dist /app/frontend/dist

# Create output directory for SQLite database
RUN mkdir -p /app/output

# Expose Flask port
EXPOSE 5000

# Health check — hit the dashboard stats endpoint
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD wget -qO- http://localhost:5000/api/dashboard/stats || exit 1

# Run the server
CMD ["python", "server.py"]
