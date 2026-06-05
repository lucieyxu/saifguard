# Stage 1: Build dependencies
FROM python:3.11-slim-bookworm AS builder

WORKDIR /app


RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

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

ENV PORT=8080
EXPOSE 8080

ENTRYPOINT ["./entrypoint.sh"]
