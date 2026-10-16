.PHONY: setup test lint run demo

setup:
	uv sync --locked

test:
	uv run --locked python -m pytest

lint:
	uv run --locked ruff check .

run:
	uv run --locked python -m aegisforge

demo:
	uv run --locked streamlit run streamlit_app.py
