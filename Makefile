.PHONY: all test format lint py

all: format lint test py

test:
	uv run -m unittest discover -b

format:
	uvx isort .
	uvx black .

lint:
	uv run mypy --strict .

py:
	uv build
