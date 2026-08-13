.PHONY: compile test policy architecture source-contracts liquidation-mechanisms all

PYTHON ?= python3
export PYTHONPATH := src

compile:
	$(PYTHON) -m compileall -q src tests scripts

test:
	$(PYTHON) -m unittest discover -s tests -v

policy:
	$(PYTHON) scripts/check_repo_policy.py

architecture:
	$(PYTHON) scripts/verify_architecture_lock.py

source-contracts:
	$(PYTHON) scripts/verify_source_contracts.py

liquidation-mechanisms:
	$(PYTHON) scripts/verify_liquidation_mechanisms.py

all: compile test policy architecture source-contracts liquidation-mechanisms
