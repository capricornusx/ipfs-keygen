# Canonical Makefile template for ipfs-media Go services.
# Source of truth: ci-templates/make/go.mk — copy to your repo root as Makefile
# and adjust the variables below. Keep the target contract intact:
#
#   all build test test-race lint lint-fix coverage deps clean release-check help
#
# CI (templates/go-service.yml) calls `make lint`, `make test`, `make test-race`,
# `make coverage` — command flags live here, not in the pipeline.

# ---- Repo-specific variables (adjust these) ---------------------------------

BINARY   ?= ipfs-key      # output binary name (dist/$(BINARY))
CMD      ?= .             # main package to build (main.go in repo root)
DIST     ?= dist
LDFLAGS  ?= -s -w         # add -X main.version=... here if the repo stamps versions
GCFLAGS  ?= -B            # go build -gcflags="-B" (disable bounds-check elimination)

# GOWORK=off: build standalone, ignoring the workspace go.work.
# Clear it (GOWORK=) only if the repo relies on replace directives from go.work.
GOWORK   ?= off

# ---- Tooling ----------------------------------------------------------------

GOLANGCI      ?= golangci-lint
LINT_TIMEOUT  ?= 5m

export GOWORK

.DEFAULT_GOAL := all

.PHONY: all build test test-race lint lint-fix coverage deps clean release-check help run

all: build ## Default: build the binary

build: ## Build binary into dist/
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -gcflags "$(GCFLAGS)" -o $(DIST)/$(BINARY) $(CMD)

test: ## Run unit tests (short mode, как в CI verify)
	go test ./... -count=1 -short

test-race: ## Run tests with race detector (CI: allow_failure)
	go test -race -count=1 -short ./...

lint: ## Static analysis, read-only (formatting violations included)
	$(GOLANGCI) run --timeout=$(LINT_TIMEOUT)

lint-fix: ## Autofix lint and formatting (rewrites files)
	$(GOLANGCI) run --timeout=$(LINT_TIMEOUT) --fix
	gofmt -w .

coverage: ## Test coverage summary (writes coverage.out)
	go test -coverprofile=coverage.out -covermode=atomic ./...
	go tool cover -func=coverage.out

deps: ## Tidy and download modules
	go mod tidy
	go mod download

clean: ## Remove build artifacts
	rm -rf $(DIST) coverage.out

release-check: lint test ## Pre-tag gate called by lefthook release-gate
	@if command -v govulncheck >/dev/null 2>&1; then \
		govulncheck ./...; \
	else \
		echo "govulncheck not installed, skipping (go install golang.org/x/vuln/cmd/govulncheck@latest)"; \
	fi

run: build ## Run keygen with the fixed suffix list
	@./$(DIST)/$(BINARY) -timeout=10m -mode=ipns -suff=kubo,bench,release,latest,swarmagent,bbuild,abuild,petabyte,science

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'
