# oscal-aap-ansible-playbooks -- single entrypoint for every routine task.
#
# Targets that are not implemented yet print an explicit SKIP naming the pull
# request that delivers them. They never pretend to have succeeded: a
# compliance toolchain that reports green for work it did not do is precisely
# the failure mode this project exists to avoid.

SHELL := /bin/bash
.DEFAULT_GOAL := help

VENV        ?= .venv
# BIN is a command PREFIX, not a directory. It resolves to the virtualenv when
# one exists (local development) and to empty when it does not (CI, where pip
# installs onto PATH). This keeps `make lint` identical in both places -- a
# green laptop and a green pull request should mean the same thing.
BIN         ?= $(if $(wildcard $(VENV)/bin/python),$(VENV)/bin/,)
PY          ?= $(BIN)python
PIP         ?= $(VENV)/bin/pip
COLLECTIONS ?= collections
OUT         ?= out

# Pinned upstream ISM OSCAL release. Bump via the release-watch workflow, never by hand.
ISM_RELEASE ?= v2026.09.4
ISM_MIRROR  ?= https://github.com/AustralianCyberSecurityCentre/ism-oscal

# Default baseline for coverage and local assessment runs.
BASELINE    ?= E8_ML1

.PHONY: help bootstrap deps lint docs generate validate test assess-local coverage fetch clean

help: ## Show this help
	@awk 'BEGIN{FS=":.*?## "} /^[a-zA-Z_-]+:.*?## /{printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

bootstrap: ## Create the virtualenv and install pinned Python tooling
	python3 -m venv $(VENV)
	$(PIP) install --quiet --upgrade pip
	$(PIP) install --quiet -r requirements.txt
	@echo "bootstrap OK -> $$($(VENV)/bin/python -V), $$($(VENV)/bin/ansible --version | head -1)"

deps: ## Install Ansible collection dependencies into collections/
	$(BIN)ansible-galaxy collection install -r requirements.yml -p $(COLLECTIONS) --force

lint: ## Lint YAML, Ansible (production profile) and Python
	$(BIN)yamllint --strict .
	$(BIN)ansible-lint
	$(BIN)ruff check tools tests
	$(MAKE) docs

docs: ## Check that every relative documentation link resolves
	$(BIN)python tools/check_doc_links.py

generate: ## Regenerate derived OSCAL artefacts (component-definitions)
	$(BIN)python tools/cca.py generate

validate: ## Validate vendored data, OSCAL artefacts and the check registry
	$(BIN)python tools/fetch_ism_oscal.py --verify --release $(ISM_RELEASE)
	$(BIN)python tools/oscal_validate.py
	$(BIN)python tools/cca.py validate-registry

fetch: ## Download + checksum the pinned ACSC ISM OSCAL release and NIST schemas
	$(BIN)python tools/fetch_ism_oscal.py --release $(ISM_RELEASE)

test: ## Run the Python unit test suite
	$(BIN)python -m pytest tests/ -q

assess-local: ## End-to-end evaluate -> emit using the bundled fixtures
	$(BIN)python tools/cca.py evaluate tests/fixtures/bundles/*.json \
		--baseline $(BASELINE) --system-id LOCAL --run-id local:$(shell date +%s) \
		--population-total 50 --out $(OUT)

coverage: ## Report control coverage for a baseline (honest, not flattering)
	$(BIN)python tools/cca.py coverage --baseline $(BASELINE)

clean: ## Remove generated output and caches
	rm -rf $(OUT) .pytest_cache .ruff_cache .mypy_cache htmlcov .coverage
	find . -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true
