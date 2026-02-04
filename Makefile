.PHONY: all build test clean scan lint docker-build docker-push help

define banner
	@echo "========================================================="
	@echo "  TARGET: $(1)"
	@echo "========================================================="
endef

all: lint scan test build

build:
	$(call banner,$@)
	go build ./...  

test:
	$(call banner,$@)
	go test -race -cover ./...

test-coverage:
	$(call banner,$@)
	go test -v -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out
	rm coverage.out

lint:
	$(call banner,$@)
	golangci-lint run ./...

scan:
	$(call banner,$@)
	govulncheck ./...

tidy:
	$(call banner,$@)
	go mod tidy
	go fmt ./...

doc:
	$(call banner,$@)
	pkgsite -open .

clean:
	rm -rf bin
	go clean

help:
	@echo "Usage: make [target]"
