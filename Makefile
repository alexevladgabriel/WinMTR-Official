# WinMTR-Official — Go port of mtr
# Pure Go (CGO disabled): cross-compiles to every target without a C toolchain.

BINARY    := mtr
PKG       := ./cmd/mtr
MODULE    := github.com/WinMTR/WinMTR-Official

# Version stamped from git (tag or short SHA); overridable: `make VERSION=1.2.3`.
VERSION   ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS   := -s -w -X main.version=$(VERSION)

# Release matrix. Add/remove os/arch pairs here.
PLATFORMS := \
	linux/amd64 linux/arm64 \
	darwin/amd64 darwin/arm64 \
	windows/amd64 windows/386 windows/arm64

DIST      := dist

export CGO_ENABLED := 0

.DEFAULT_GOAL := build

.PHONY: build
build: ## Build for the host OS/arch
	go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY) $(PKG)

.PHONY: windows
windows: ## Build mtr.exe for windows/amd64 (replaces the repo-root binary)
	GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY).exe $(PKG)

.PHONY: release
release: ## Cross-compile every platform in PLATFORMS into dist/
	@mkdir -p $(DIST)
	@for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; \
		ext=""; [ "$$os" = "windows" ] && ext=".exe"; \
		out="$(DIST)/$(BINARY)-$(VERSION)-$$os-$$arch$$ext"; \
		echo "  build $$out"; \
		GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags "$(LDFLAGS)" -o "$$out" $(PKG) || exit 1; \
	done
	@echo "release binaries in $(DIST)/"

.PHONY: test
test: ## Run tests with the race detector
	go test -race ./...

.PHONY: vet
vet: ## Run go vet
	go vet ./...

.PHONY: fmt
fmt: ## Format all Go sources
	gofmt -w .

.PHONY: tidy
tidy: ## Sync go.mod/go.sum
	go mod tidy

.PHONY: check
check: vet test ## Vet + test (CI gate)

.PHONY: clean
clean: ## Remove build artifacts
	rm -rf $(DIST) $(BINARY) $(BINARY).exe

.PHONY: help
help: ## List targets
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | \
		awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'
