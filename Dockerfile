# syntax=docker/dockerfile:1

FROM ghcr.io/astral-sh/uv:0.13.0 AS uv
FROM python:3.11.2-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_COMPILE_BYTECODE=1 \
    PATH="/app/.venv/bin:$PATH"

WORKDIR /app

COPY --from=uv /uv /uvx /usr/local/bin/
COPY pyproject.toml uv.lock README.md ./

RUN uv sync --locked --no-dev --no-install-project

COPY src/ src/

RUN uv sync --locked --no-dev

ENTRYPOINT ["python", "-m", "aegisforge"]
