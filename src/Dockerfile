# Stage 1: Build dependencies with uv
FROM python:3.11-slim-bookworm AS builder

# Install uv binary from official Astral image
COPY --from=ghcr.io/astral-sh/uv:latest /uv /bin/uv

WORKDIR /app

ENV VIRTUAL_ENV=/opt/venv
ENV PATH="/opt/venv/bin:$PATH"
ENV UV_COMPILE_BYTECODE=1

# Copy dependency specifications
COPY pyproject.toml poetry.lock ./

# Create virtual environment and install dependencies using uv
RUN uv venv /opt/venv && \
    uv pip install -r pyproject.toml

# Stage 2: Final runtime image
FROM python:3.11-slim-bookworm

WORKDIR /app

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
ENV PYTHONPATH="/app"

# Copy source code
COPY . .

# Ensure entrypoint is executable
RUN chmod +x entrypoint.sh

# Create non-root user
RUN groupadd -r appgroup && useradd -r -g appgroup -d /app appuser
RUN chown -R appuser:appgroup /app

USER appuser

ENV TZ="Europe/Paris"
ENV PORT=8080
EXPOSE 8080

ENTRYPOINT ["./entrypoint.sh"]
