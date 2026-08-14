.PHONY: compile test policy architecture source-contracts f2-schemas f3-schemas f4-schemas all
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
f2-schemas:
	$(PYTHON) scripts/verify_f2_schemas.py
f3-schemas:
	$(PYTHON) scripts/verify_f3_schemas.py
f4-schemas:
	$(PYTHON) scripts/verify_f4_schemas.py
all: compile test policy architecture source-contracts f2-schemas f3-schemas f4-schemas
