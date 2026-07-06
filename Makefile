BINARY := fence
PKG := github.com/hoophq/fence
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build install test vet fmt tidy clean

build: ## Build the fence binary into ./dist
	@mkdir -p dist
	go build -ldflags "$(LDFLAGS)" -o dist/$(BINARY) ./cmd/fence

install: ## Install fence into $GOBIN / $GOPATH/bin
	go install -ldflags "$(LDFLAGS)" ./cmd/fence

test: ## Run all tests
	go test ./...

vet: ## Run go vet
	go vet ./...

fmt: ## Format the code
	gofmt -s -w .

tidy: ## Tidy go.mod / go.sum
	go mod tidy

clean: ## Remove build artifacts
	rm -rf dist
