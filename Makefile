.PHONY: all test format lint py

all: format lint test py

test:
	uv run -m unittest discover

format:
	uvx isort .
	uvx black .

lint:
	uv run mypy --strict fastapi_simple_oauth2

py:
	uv build
