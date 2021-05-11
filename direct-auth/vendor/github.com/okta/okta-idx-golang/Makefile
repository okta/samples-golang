COLOR_OK=\\x1b[0;32m
COLOR_NONE=\x1b[0m
COLOR_ERROR=\x1b[31;01m
COLOR_WARNING=\x1b[33;01m
COLOR_OKTA=\x1B[34;01m

GOLINT=golangci-lint

VERSION=$(shell grep -E -o '(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?' ./idx.go | head -n 1 )

help:
	@make heading
	@echo "$(COLOR_WARNING)Usage:$(COLOR_NONE)"
	@echo "$(COLOR_OK)  make [command]$(COLOR_NONE)"
	@echo ""
	@echo "$(COLOR_WARNING)Available commands:$(COLOR_NONE)"
	@echo "$(COLOR_OK)  help$(COLOR_NONE)       Show this help message"
	@echo "$(COLOR_OK)  dep$(COLOR_NONE)        Download required dependencies"
	@echo "$(COLOR_OK)  check-lint$(COLOR_NONE) Downloads golangci-lint if not installed on system"
	@echo "$(COLOR_OK)  lint$(COLOR_NONE)       Run golint"
	@echo ""
	@echo "$(COLOR_WARNING)test$(COLOR_NONE)"
	@echo "$(COLOR_OK)  test:all                Test All, Unit, and Integration$(COLOR_NONE)"
	@echo "$(COLOR_OK)  test:integration        Run Integration Tests$(COLOR_NONE)"
	@echo "$(COLOR_OK)  test:unit               Run Unit Tests$(COLOR_NONE)"

dep: # Download required dependencies
	go mod vendor

.PHONY: check-lint
check-lint:
	@which $(GOLINT) || curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(shell go env GOPATH)/bin v1.33.0

.PHONY: lint
lint: heading check-lint
	$(GOLINT) run -c .golangci.yml

test:
	@make heading
	@make dep
	make test:all

test\:all:
	@echo "$(COLOR_OKTA)Running all tests...$(COLOR_NONE)"
	@make test:unit
	@make test:integration

test\:integration:
	@echo "$(COLOR_OKTA)Running integration tests...$(COLOR_NONE)"
	go test -tags integration -mod=vendor -test.v

test\:unit:
	@echo "$(COLOR_OK)Running unit tests...$(COLOR_NONE)"
	go test -tags unit -mod=vendor -test.v

.PHONY: heading
heading:
	@echo "$(COLOR_OKTA)  ___  _  _______  _$(COLOR_NONE)"
	@echo "$(COLOR_OKTA) / _ \| |/ /_   _|/ \ $(COLOR_NONE)"
	@echo "$(COLOR_OKTA)| | | | ' /  | | / _ \ $(COLOR_NONE)"
	@echo "$(COLOR_OKTA)| |_| | . \  | |/ ___ \ $(COLOR_NONE)"
	@echo "$(COLOR_OKTA) \___/|_|\_\ |_/_/   \_\ $(COLOR_NONE)"
	@echo ""
	@echo "$(COLOR_OK)Okta IDX Golang$(COLOR_NONE) version $(COLOR_WARNING)$(VERSION)$(COLOR_NONE)"
	@echo ""