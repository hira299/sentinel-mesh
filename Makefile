.PHONY: install run benchmark visualize clean help

PYTHON     := python3
VENV       := .venv
PIP        := $(VENV)/bin/pip
VENV_PY    := $(VENV)/bin/python

# ── Setup ──────────────────────────────────────────────────────────────────

install:
	$(PYTHON) -m venv $(VENV)
	$(PIP) install --upgrade pip
	$(PIP) install -r requirements.txt
	@echo "Environment ready. Activate with: source $(VENV)/bin/activate"

# ── Core ───────────────────────────────────────────────────────────────────

run:
	$(VENV_PY) experiment_runner.py

benchmark:
	$(VENV_PY) experiment_runner.py --all
	@echo "Results written to logs/research_data_v100.csv"

visualize:
	$(VENV_PY) core/visualizer.py
	@echo "Figures saved to logs/"

# ── Housekeeping ───────────────────────────────────────────────────────────

clean:
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	rm -rf logs/*.png

help:
	@echo ""
	@echo "  install     create venv and install dependencies"
	@echo "  run         run experiment_runner on default config"
	@echo "  benchmark   run full 105-case benchmark"
	@echo "  visualize   generate result figures from latest CSV"
	@echo "  clean       remove cache files and generated figures"
	@echo ""