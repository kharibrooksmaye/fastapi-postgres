FROM python:3.13-slim as builder
WORKDIR /app
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    libpq-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

RUN pip install poetry

ENV POETRY_NO_INTERACTION=1 \
    POETRY_VENV_IN_PROJECT=1 \
    POETRY_CACHE_DIR=/tmp/poetry_cache

COPY pyproject.toml poetry.lock ./

# Install dependencies using poetry
RUN poetry install --only=main && rm -rf $POETRY_CACHE_DIR

# Stage 2: Create the final lightweight image
FROM python:3.13-slim as production

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    curl \
    libpq5 \
    && rm -rf /var/lib/apt/lists/*

# Install pip
RUN pip install --no-cache-dir poetry

# Set working directory
WORKDIR /app

# Create non-root user
RUN addgroup --system --gid 1001 appgroup && \
    adduser --system --uid 1001 --gid 1001 appuser

# Copy pyproject files and install dependencies
COPY pyproject.toml poetry.lock ./
RUN poetry config virtualenvs.create false && poetry install --only=main

# Copy application code
COPY --chown=appuser:appgroup . .

# Switch to non-root user
USER appuser

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Expose port
EXPOSE 8000

# Start application
CMD ["uvicorn", "app.main:app", \
     "--host", "0.0.0.0", \
     "--port", "8000", \
     "--workers", "1"]