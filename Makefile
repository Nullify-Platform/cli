.PHONY: build clean deploy

# set the version as the latest commit sha if it's not already defined
ifndef VERSION
# check if there are code changes that aren't commited
# add a -tainted label to the end of the version if there are
ifneq ($(shell git status --porcelain), )
TAINT := -tainted
endif
VERSION := $(shell git rev-list -1 HEAD)$(TAINT)
endif

GOENV := CGO_ENABLED=0
GOFLAGS := -ldflags "-X 'github.com/nullify-platform/logger/pkg/logger.Version=$(VERSION)'"

all: build

build:
	$(GOENV) go build $(GOFLAGS) -o bin/cli ./cmd/cli/...

package:
	# linux
	$(GOENV) GOOS=linux   GOARCH=amd64 go build $(GOFLAGS) -o bin/nullify_linux_amd64_$(VERSION) ./cmd/cli/...
	$(GOENV) GOOS=linux   GOARCH=arm64 go build $(GOFLAGS) -o bin/nullify_linux_arm64_$(VERSION) ./cmd/cli/...
	$(GOENV) GOOS=linux   GOARCH=386   go build $(GOFLAGS) -o bin/nullify_linux_386_$(VERSION)   ./cmd/cli/...
	# mac
	$(GOENV) GOOS=darwin  GOARCH=amd64 go build $(GOFLAGS) -o bin/nullify_macos_amd64_$(VERSION) ./cmd/cli/...
	$(GOENV) GOOS=darwin  GOARCH=arm64 go build $(GOFLAGS) -o bin/nullify_macos_arm64_$(VERSION) ./cmd/cli/...
	# windows
	$(GOENV) GOOS=windows GOARCH=amd64 go build $(GOFLAGS) -o bin/nullify_windows_amd64_$(VERSION).exe ./cmd/cli/...
	$(GOENV) GOOS=windows GOARCH=386   go build $(GOFLAGS) -o bin/nullify_windows_386_$(VERSION).exe   ./cmd/cli/...

clean:
	rm -rf ./bin ./vendor Gopkg.lock coverage.*

format: 
	gofmt -w ./...

lint: lint-go lint-docker

lint-go:
	docker build --quiet --target golangci-lint -t golangci-lint:latest .
	docker run --rm -v $(shell pwd):/app -w /app golangci-lint golangci-lint run ./...

lint-docker:
	docker build --quiet --target hadolint -t hadolint:latest .
	docker run --rm -v $(shell pwd):/app -w /app hadolint hadolint Dockerfile demo_server/Dockerfile

unit:
	go test -v -skip TestIntegration ./...

cov:
	-go test -coverpkg=./... -coverprofile=coverage.txt -covermode count ./...
	-gocover-cobertura < coverage.txt > coverage.xml
	-go tool cover -html=coverage.txt -o coverage.html
	-go tool cover -func=coverage.txt
