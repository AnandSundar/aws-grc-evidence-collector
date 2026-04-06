.PHONY: install deploy test destroy collect report lint check clean

install:
	pip install -r requirements.txt

deploy:
	python scripts/deploy_cloudformation.py

deploy-quick:
	python scripts/setup.py

test:
	pytest tests/ -v --cov=collectors --cov=remediations

test-integration:
	python tests/test_events.py

destroy:
	python scripts/teardown.py

collect:
	python scripts/run_all_collectors.py

report:
	python scripts/generate_report.py --type full --period 24h

lint:
	cfn-lint cloudformation/*.yaml
	checkov -d cloudformation/ --framework cloudformation
	checkov -d lambda/ collectors/ remediations/ --framework python_code

check: lint test

clean:
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -name "*.pyc" -delete
	rm -f grc_config.json
