# JSCR has no mandatory dependencies, so every target here runs on a plain
# Python install. Targets that need a linter say so and skip cleanly.

PYTHON ?= python3
export PYTHONPATH := src

.PHONY: help test lint types check selfreview egress-audit ground-truth clean

help:
	@echo "test          run the test suite (stdlib unittest, no install needed)"
	@echo "lint          ruff, if it is installed"
	@echo "types         mypy, if it is installed"
	@echo "egress-audit  prove only egress/http.py can reach the network"
	@echo "ground-truth  score the scanners against planted defects"
	@echo "selfreview    run jscr over its own working tree"
	@echo "check         test + egress-audit + lint + types"
	@echo "clean         remove build output and caches only"

test:
	$(PYTHON) -m unittest discover -s tests -t . -v

# The presence check is separate from the run. Chaining them with && and ||
# turned a real lint failure into "not installed, skipped" and exit 0.
lint:
	@if $(PYTHON) -m ruff --version >/dev/null 2>&1; then \
		$(PYTHON) -m ruff check src tools tests \
		&& $(PYTHON) -m ruff format --check src tools tests; \
	else \
		echo "ruff not installed, skipped"; \
	fi

types:
	@if $(PYTHON) -m mypy --version >/dev/null 2>&1; then \
		$(PYTHON) -m mypy src; \
	else \
		echo "mypy not installed, skipped"; \
	fi

# The claim "nothing else can reach the network" is checkable, so it is
# checked. Any module other than egress/http.py importing a network library
# fails this target.
egress-audit:
	@$(PYTHON) tools/egress_audit.py

# Coverage says the rules ran. This says they found the defects they were
# written for, and stayed quiet on code that only looks like a defect.
ground-truth:
	@$(PYTHON) tools/ground_truth.py

selfreview:
	$(PYTHON) -m jscr review --worktree -v

check: test egress-audit ground-truth lint types

# Deliberately a script rather than a wildcard shell command: it removes a
# named, closed set of generated directories and nothing else.
clean:
	@$(PYTHON) tools/clean.py
