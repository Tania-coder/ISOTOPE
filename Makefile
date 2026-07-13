PY ?= python3

.PHONY: verify lint test invariants clean

verify: lint test invariants
	@echo "VERIFY PASSED"

lint:
	$(PY) -m compileall -q src tests scripts
	$(PY) -m ruff check src tests scripts

test:
	$(PY) -m pytest

invariants:
	$(PY) scripts/check_invariants.py --iterations 500

clean:
	find . -type d -name __pycache__ -exec rm -rf {} +
