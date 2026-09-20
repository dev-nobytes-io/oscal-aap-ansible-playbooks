# oscal-aap-ansible-playbooks -- single entrypoint for every routine task.
#
# Targets that are not implemented yet print an explicit SKIP naming the pull
# request that delivers them. They never pretend to have succeeded: a
# compliance toolchain that reports green for work it did not do is precisely
# the failure mode this project exists to avoid.

SHELL := /bin/bash
.DEFAULT_GOAL := help

VENV        ?= .venv
PY          ?= $(VENV)/bin/python
PIP         ?= $(VENV)/bin/pip
BIN         ?= $(VENV)/bin
COLLECTIONS ?= collections
OUT         ?= out

# Pinned upstream ISM OSCAL release. Bump via the release-watch workflow, never by hand.
ISM_RELEASE ?= v2026.09.4
ISM_MIRROR  ?= https://github.com/AustralianCyberSecurityCentre/ism-oscal

.PHONY: help bootstrap deps lint validate test assess-local coverage fetch clean

help: ## Show this help
	@awk 'BEGIN{FS=":.*?## "} /^[a-zA-Z_-]+:.*?## /{printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

bootstrap: ## Create the virtualenv and install pinned Python tooling
	python3 -m venv $(VENV)
	$(PIP) install --quiet --upgrade pip
	$(PIP) install --quiet -r requirements.txt
	@echo "bootstrap OK -> $$($(PY) -V), $$($(BIN)/ansible --version | head -1)"

deps: ## Install Ansible collection dependencies into collections/
	$(BIN)/ansible-galaxy collection install -r requirements.yml -p $(COLLECTIONS) --force

lint: ## Lint YAML, Ansible (production profile) and Python
	$(BIN)/yamllint --strict .
	$(BIN)/ansible-lint
	$(BIN)/ruff check tools tests

validate: ## Validate every OSCAL artefact against the pinned NIST 1.1.2 schemas
	@echo "SKIP: validate lands in PR 03 (OSCAL ingest)."

fetch: ## Download + checksum the pinned ACSC ISM OSCAL release
	@echo "SKIP: fetch lands in PR 03 (OSCAL ingest). Pinned release: $(ISM_RELEASE)"

test: ## Run the Python unit test suite
	@echo "SKIP: test lands in PR 04 (check contract + evaluator)."

assess-local: ## End-to-end collect -> evaluate -> emit against localhost
	@echo "SKIP: assess-local lands in PR 04 (check contract + evaluator)."

coverage: ## Regenerate the control-coverage ledger
	@echo "SKIP: coverage lands in PR 04 (check contract + evaluator)."

clean: ## Remove generated output and caches
	rm -rf $(OUT) .pytest_cache .ruff_cache .mypy_cache htmlcov .coverage
	find . -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true
