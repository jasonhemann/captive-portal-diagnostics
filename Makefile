.PHONY: sync format lint lint-fix typecheck test smoke coverage check check-env build install clean

UV ?= uv
PYTHON_VERSION ?= 3.13
APP_NAME := captive-portal-diagnose
ENTRYPOINT := src/captive_portal_diagnostics/__main__.py
INSTALL_DIR ?= $(HOME)/.local/bin

sync:
	$(UV) sync --python $(PYTHON_VERSION) --group dev

format:
	$(UV) run --python $(PYTHON_VERSION) ruff format src tests

lint:
	$(UV) run --python $(PYTHON_VERSION) ruff check src tests

lint-fix:
	$(UV) run --python $(PYTHON_VERSION) ruff check src tests --fix

typecheck:
	$(UV) run --python $(PYTHON_VERSION) basedpyright

test:
	$(UV) run --python $(PYTHON_VERSION) pytest -q

smoke:
	$(UV) run --python $(PYTHON_VERSION) captive-portal-diagnose --help >/dev/null
	$(UV) run --python $(PYTHON_VERSION) captive-portal-safe-review --help >/dev/null

coverage:
	@echo "Coverage target (warn-only in wave 1): 80%"
	-$(UV) run --python $(PYTHON_VERSION) pytest --cov=src/captive_portal_diagnostics --cov-report=term-missing -q

check: lint typecheck test smoke

check-env:
	@echo "Python:" && $(UV) run --python $(PYTHON_VERSION) python -V
	@echo "Interpreter Path:" && $(UV) run --python $(PYTHON_VERSION) python -c "import sys; print(sys.executable)"
	@echo "Virtualenv Prefix:" && $(UV) run --python $(PYTHON_VERSION) python -c "import sys; print(sys.prefix)"

build: sync
	$(UV) run --python $(PYTHON_VERSION) pyinstaller --onefile --name $(APP_NAME) $(ENTRYPOINT)

install: build
	install -m 755 ./dist/$(APP_NAME) $(INSTALL_DIR)/$(APP_NAME)

clean:
	rm -rf .venv __pycache__ */__pycache__ .pytest_cache .ruff_cache dist build *.egg-info *.spec
