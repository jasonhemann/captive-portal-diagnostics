.PHONY: sync format lint typecheck test check

UV ?= uv

sync:
	$(UV) sync --group dev

format:
	$(UV) run ruff format src tests

lint:
	$(UV) run ruff check src tests

typecheck:
	$(UV) run basedpyright

test:
	$(UV) run pytest

check: lint typecheck test
