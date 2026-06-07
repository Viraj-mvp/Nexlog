# NexLog developer shortcuts

PYTHON ?= python
LOG ?= examples/logs/Apache_2k.log

.PHONY: help test test-security test-ai test-gui smoke gui api clean release-check source-zip docker-build

help:
	@echo "NexLog targets"
	@echo "  make smoke          Run CLI/GUI/API help checks"
	@echo "  make test           Run key unit suites"
	@echo "  make gui            Launch the QML GUI"
	@echo "  make api            Launch the API"
	@echo "  make clean          Remove generated artifacts"
	@echo "  make release-check  Run release readiness checks"
	@echo "  make source-zip     Build clean source ZIP"
	@echo "  make docker-build   Build Docker image"

smoke:
	@$(PYTHON) -B main.py --help
	@$(PYTHON) -B main_gui.py --help
	@$(PYTHON) -B main_gui.py --packaged-check
	@$(PYTHON) -B -m interface.web.serve --help
	@$(PYTHON) -B main.py $(LOG) --case workspace/smoke.facase --report none --quiet

test: test-security test-ai test-gui

test-security:
	@$(PYTHON) -B -m pytest tests/unit/test_security.py -q -p no:cacheprovider

test-ai:
	@$(PYTHON) -B -m pytest tests/unit/test_ai.py -q -p no:cacheprovider

test-gui:
	@$(PYTHON) -B -m pytest tests/unit/test_layer5_gui.py -q -p no:cacheprovider

gui:
	@$(PYTHON) main_gui.py

api:
	@$(PYTHON) -m interface.web.serve --host 127.0.0.1 --port 8000

clean:
	@$(PYTHON) scripts/clean_project.py --apply

release-check:
	@$(PYTHON) scripts/release_check.py

source-zip:
	@$(PYTHON) scripts/package_release.py --source-zip --skip-check

docker-build:
	@docker build -f packaging/Dockerfile -t nexlog:latest .
