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

# Pinned ASD Blueprint for Secure Cloud release. Only the cited pages and the
# submission templates are vendored -- see tools/fetch_blueprint.py.
BLUEPRINT_RELEASE ?= v1.4.0

# Default baseline for coverage and local assessment runs.
BASELINE    ?= E8_ML1

.PHONY: help bootstrap deps lint docs generate validate test assess-local coverage report annex fetch clean ee-context ee-build

help: ## Show this help
	@awk 'BEGIN{FS=":.*?## "} /^[a-zA-Z_-]+:.*?## /{printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

bootstrap: ## Create the virtualenv and install pinned Python tooling
	python3 -m venv $(VENV)
	$(PIP) install --quiet --upgrade pip
	$(PIP) install --quiet -r requirements.txt
	# Editable install so the `cca` console script exists locally and the
	# package layout is exercised the same way an execution environment does.
	$(PIP) install --quiet -e .
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
	$(BIN)python tools/fetch_eol_data.py --verify
	$(BIN)python tools/fetch_blueprint.py --verify
	$(BIN)python tools/oscal_validate.py
	$(BIN)python tools/cca.py validate-registry

fetch: ## Download + checksum the ISM OSCAL release, NIST schemas, EOL and Blueprint data
	$(BIN)python tools/fetch_ism_oscal.py --release $(ISM_RELEASE)
	$(BIN)python tools/fetch_eol_data.py
	$(BIN)python tools/fetch_blueprint.py --release $(BLUEPRINT_RELEASE)

test: ## Run the Python unit test suite
	$(BIN)python -m pytest tests/ -q

assess-local: ## End-to-end evaluate -> emit using the bundled fixtures
	$(BIN)python tools/cca.py evaluate tests/fixtures/bundles/*.json \
		--baseline $(BASELINE) --system-id LOCAL --run-id local:$(shell date +%s) \
		--population-total 50 --out $(OUT)

report: ## Render the human-readable assessment report (markdown + html)
	$(BIN)python tools/cca.py report --format markdown
	$(BIN)python tools/cca.py report --format html

annex: ## Populate ASD's SSP Annex from the assessment results
	$(BIN)python tools/cca.py annex

coverage: ## Report control coverage for a baseline (honest, not flattering)
	$(BIN)python tools/cca.py coverage --baseline $(BASELINE)

# --- Execution environments -------------------------------------------------
#
# EE_PYCMD is the ANSIBLE-CORE controller interpreter inside the image, and it
# has to be passed explicitly: ansible-core 2.16 requires Python >= 3.10 and
# 2.19 requires >= 3.11, while the CentOS Stream 9 base ships 3.9 as
# /usr/bin/python3. We deliberately leave /usr/bin/python3 alone -- dnf runs on
# it, and it is the interpreter the evaluator is invoked with -- so the
# controller Python is selected here instead. ansible-builder v3 restricts
# build_arg_defaults to a fixed set of keys, so this cannot live in the
# definition file.
EE          ?= ee-current
EE_PYCMD    ?= /usr/bin/python3.11
EE_TAG      ?= nobytes-cca/$(EE):dev
EE_DEF       = aap/execution-environment/$(EE)/execution-environment.yml
# Pinned rather than auto-detected. ansible-builder picks podman when it is
# installed, and CI inspects the result with `docker run` -- an image built into
# the other runtime's store simply is not there. Override for a podman host.
EE_RUNTIME  ?= docker

ee-context: ## Render an EE build context without building (no container runtime needed)
	$(BIN)ansible-builder create -f $(EE_DEF) -c $(OUT)/ee-context-$(EE)
	@test -d "$(OUT)/ee-context-$(EE)/_build/nobytes_cca" || { \
	  echo "ERROR: _build/nobytes_cca is missing -- additional_build_files is wrong"; \
	  exit 1; }
	@echo "context OK -> $(OUT)/ee-context-$(EE) (evaluator staged for COPY)"

ee-build: ## Build an execution environment image (EE=ee-current|ee-legacy)
	# -c keeps the generated context under $(OUT); without it ansible-builder
	# drops a `context/` directory in the repository root.
	$(BIN)ansible-builder build -f $(EE_DEF) -t $(EE_TAG) \
	  -c $(OUT)/ee-context-$(EE) --build-arg PYCMD=$(EE_PYCMD) \
	  --container-runtime $(EE_RUNTIME) -v 2

clean: ## Remove generated output and caches
	rm -rf $(OUT) .pytest_cache .ruff_cache .mypy_cache htmlcov .coverage
	find . -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true
