# Developer tasks for the AWS Cost Optimizer.
#
# These mirror what CI runs (.github/workflows/ci.yml), so a green
# `make check` locally should mean a green pipeline.
#
# On Windows without `make`, run the underlying commands directly --
# they are plain python -m invocations with no shell-specific syntax.

PYTHON ?= python
PY_DIRS = aws_cost_optimizer backend tests

.PHONY: help install fmt fmt-check test check

help:
	@echo "install    - install runtime + dev dependencies"
	@echo "fmt        - format Python code with black (line length 88)"
	@echo "fmt-check  - verify formatting without writing changes (CI)"
	@echo "test       - run the pytest suite"
	@echo "check      - fmt-check + test"

install:
	$(PYTHON) -m pip install -r requirements.txt -r requirements-dev.txt

fmt:
	$(PYTHON) -m black -l 88 $(PY_DIRS)

fmt-check:
	$(PYTHON) -m black -l 88 --check $(PY_DIRS)

test:
	$(PYTHON) -m pytest tests/ -q

check: fmt-check test
