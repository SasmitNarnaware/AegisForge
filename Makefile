.PHONY: setup test lint run

setup:
	uv sync --locked

test:
	uv run --locked python -m pytest

lint:
	uv run --locked ruff check .

run:
	uv run --locked python -m aegisforge
