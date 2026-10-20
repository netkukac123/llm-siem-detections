PY ?= python3
WAZUH_IMAGE ?= wazuh/wazuh-manager:4.14.7
KUSTAINER_IMAGE ?= mcr.microsoft.com/azuredataexplorer/kustainer-linux@sha256:51e2250da2faf292de903f871a073eb37d3f2641cf63381b183879d21ebb1013

.PHONY: dataset coverage engines engines-down test arm

dataset:            ## regenerate datasets/sample.jsonl and labels.json
	$(PY) -m simulate
	$(PY) -m simulate.coverage

coverage:           ## regenerate docs/coverage-matrix.md
	$(PY) -m simulate.coverage

engines:            ## start Kustainer and wazuh-manager locally
	docker run -d --name kustainer-llmd -e ACCEPT_EULA=Y -p 127.0.0.1:8080:8080 $(KUSTAINER_IMAGE)
	docker run -d --name wazuh-llmd $(WAZUH_IMAGE)
	timeout 300 bash -c 'until docker exec wazuh-llmd test -S /var/ossec/queue/sockets/logtest; do sleep 3; done'

engines-down:
	docker rm -f kustainer-llmd wazuh-llmd

test:               ## run all tests (engine tests skip if the containers are not running)
	$(PY) -m pytest -v

arm:                ## build the Sentinel analytic rules ARM template
	mkdir -p build
	$(PY) deploy/sentinel/rules_to_arm.py > build/llmd-analytics-rules.json
