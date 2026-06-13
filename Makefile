# gostls — developer tasks.
#
# BSD pure-Go (CGO-free) TLS 1.2 client with GOST suites. Robustness fuzzers
# guard the attacker-facing wire parsers (internal/handshake.FuzzParseMessage,
# FuzzParseExtensions); `make fuzz` drives every Fuzz target.
#
# Override any variable on the command line, e.g.:
#   make test PKG=./internal/handshake/
#   make fuzz PKG=./internal/handshake/ FUZZTIME=2m

GO          ?= go
GOLANGCI    ?= golangci-lint
PKG         ?= ./...
FUZZTIME    ?= 1m
FUZZMINTIME ?= 5s

CGO_ENABLED ?= 0
export CGO_ENABLED

.DEFAULT_GOAL := help

.PHONY: help build test cover lint lint-fix fmt vet tidy fuzz ci

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

## --- building & testing ---

build: ## Build all packages (CGO-free)
	$(GO) build $(PKG)

test: ## Run the unit/round-trip tests (replays fuzz seeds too)
	$(GO) test $(PKG)

cover: ## Run the tests and open the HTML coverage report
	$(GO) test -coverprofile=coverage.out $(PKG)
	$(GO) tool cover -html=coverage.out

## --- linting ---

lint: ## Run golangci-lint
	$(GOLANGCI) run $(PKG)

lint-fix: ## Run golangci-lint and apply autofixes
	$(GOLANGCI) run --fix $(PKG)

fmt: ## gofmt-format all Go files in place
	$(GO) fmt $(PKG)

vet: ## Run go vet
	$(GO) vet $(PKG)

tidy: ## Tidy and verify go.mod / go.sum
	$(GO) mod tidy
	$(GO) mod verify

## --- fuzzing ---

fuzz: ## Fuzz every target for FUZZTIME each (default 1m; e.g. FUZZTIME=10s)
	@for pkg in $$($(GO) list $(PKG)); do \
		for fz in $$($(GO) test $$pkg -list '^Fuzz' 2>/dev/null | grep '^Fuzz' || true); do \
			echo "=== $$pkg $$fz (fuzztime $(FUZZTIME), minimize $(FUZZMINTIME)) ==="; \
			$(GO) test $$pkg -run '^$$' -fuzz "^$$fz$$" -fuzztime $(FUZZTIME) -fuzzminimizetime $(FUZZMINTIME) || exit 1; \
		done; \
	done

## --- aggregate ---

ci: lint vet test ## Run lint + vet + tests (the pre-push gate)
