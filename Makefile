#!/usr/bin/make
PYTHON := /usr/bin/env python

lint:
	@flake8 --exclude hooks/charmhelpers --ignore=E125 hooks
	@flake8 --exclude hooks/charmhelpers --ignore=E125 unit_tests tests
	@charm proof

unit_test:
	@echo Starting unit tests...
	@$(PYTHON) /usr/bin/nosetests --nologcapture --with-coverage unit_tests

test:
	@echo Starting Amulet tests...
	# coreycb note: The -v should only be temporary until Amulet sends
	# raise_status() messages to stderr:
	#   https://bugs.launchpad.net/amulet/+bug/1320357
	@juju test -v -p AMULET_HTTP_PROXY

sync:
	@charm-helper-sync -c charm-helpers-hooks.yaml
	@charm-helper-sync -c charm-helpers-tests.yaml

publish: lint test
	bzr push lp:charms/swift-proxy
	bzr push lp:charms/trusty/swift-proxy
