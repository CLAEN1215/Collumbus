# syntax=docker/dockerfile:1
FROM python:3.12-slim AS base

# Prevent Python from writing .pyc files and buffer stdout/stderr
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    STREAMLIT_SERVER_PORT=8501 \
    STREAMLIT_SERVER_ADDRESS=0.0.0.0 \
    STREAMLIT_SERVER_HEADLESS=true \
    STREAMLIT_BROWSER_GATHER_USAGE_STATS=false

WORKDIR /app

# Copy project configuration, docs, and source files
COPY pyproject.toml README.md ./
COPY src/ ./src/
COPY config/ ./config/
COPY assets/ ./assets/
COPY data/ ./data/
COPY .streamlit/ ./.streamlit/
COPY app.py ./

# Install dependencies and package
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir .

# Create a non-root user for security hardening
RUN useradd -m -u 10001 appuser && \
    mkdir -p /app/data/history && \
    chown -R appuser:appuser /app

USER appuser

EXPOSE 8501

# Health check for AWS App Runner, ECS, and ALB
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8501/_stcore/health')" || exit 1

ENTRYPOINT ["streamlit", "run", "app.py", "--server.port=8501", "--server.address=0.0.0.0"]
