# SIH26145 demo image: builds the dashboard, then a slim Python runtime that replays the
# committed demo capture through the real pipeline and serves UI + API on one port.
# Nothing is downloaded at runtime: models, dashboard and capture are baked in.

# ---- 1. dashboard ---------------------------------------------------------------------------
FROM node:22-slim AS dashboard
WORKDIR /build/dashboard
COPY dashboard/package.json dashboard/package-lock.json ./
ENV PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1
RUN npm ci --no-audit --no-fund
COPY dashboard/ ./
RUN npm run build

# ---- 2. Python dependencies ------------------------------------------------------------------
FROM python:3.13-slim AS deps
COPY --from=ghcr.io/astral-sh/uv:0.12.7 /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PROJECT_ENVIRONMENT=/app/.venv
WORKDIR /app
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --no-dev --no-install-project
COPY src/ src/
RUN uv sync --frozen --no-dev

# ---- 3. runtime ------------------------------------------------------------------------------
FROM python:3.13-slim
RUN apt-get update && apt-get install -y --no-install-recommends libgomp1 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --home /app sih
WORKDIR /app
COPY --from=deps /app/.venv /app/.venv
COPY --from=deps /app/src /app/src
COPY --from=dashboard /build/dashboard/dist /app/dashboard/dist
COPY demo/demo.pcap /app/demo/demo.pcap
USER sih
ENV PATH=/app/.venv/bin:$PATH PYTHONUNBUFFERED=1 \
    SIH26145_INTERNAL_CIDRS=147.32.0.0/16,10.0.0.0/8,192.168.0.0/16,172.16.0.0/12
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/v1/health')"
CMD ["sih26145", "serve", "/app/demo/demo.pcap", "--speed", "2", "--loop", "--host", "0.0.0.0", "--port", "8000"]
