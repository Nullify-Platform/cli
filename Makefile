.PHONY: build clean lint lint-go lint-docker fetch-spec generate-api unit cov

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
GOFLAGS := -ldflags "-X 'github.com/nullify-platform/cli/internal/logger.Version=$(VERSION)'"

all: build

build:
	$(GOENV) go build $(GOFLAGS) -o bin/cli ./cmd/cli

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

# OpenAPI bundle sourcing. The spec is published in the (private) nullify
# monorepo; we pin a commit and vendor the bundle into spec/ so generation is
# reproducible and offline. To update: bump SPEC_REF, run `make fetch-spec`,
# then `make generate-api`, and commit both spec/ and the regenerated code.
SPEC_REF ?= 7b34970bbbeeabf665cd71fa0eb0e07eaac534a3
SPEC_REPO ?= nullify-platform/nullify
SPEC_PATH_IN_REPO ?= public-docs/.gitbook/assets/api/nullify-openapi-bundle.yaml
SPEC_LOCAL ?= spec/nullify-openapi-bundle.yaml

# fetch-spec downloads the pinned OpenAPI bundle from the monorepo. Requires
# GitHub auth (`gh auth login`) with access to the private monorepo.
fetch-spec:
	@mkdir -p $(dir $(SPEC_LOCAL))
	gh api "repos/$(SPEC_REPO)/contents/$(SPEC_PATH_IN_REPO)?ref=$(SPEC_REF)" \
		-H "Accept: application/vnd.github.raw" > $(SPEC_LOCAL)
	@echo "fetched $(SPEC_LOCAL) from $(SPEC_REPO)@$(SPEC_REF)"

generate-api:
	go run ./scripts/generate/main.go --spec $(SPEC_LOCAL) --output internal/api --cmd-output internal/commands

unit:
	go test -v -skip TestIntegration ./...

cov:
	-go test -coverpkg=./... -coverprofile=coverage.txt -covermode count ./...
	-gocover-cobertura < coverage.txt > coverage.xml
	-go tool cover -html=coverage.txt -o coverage.html
	-go tool cover -func=coverage.txt
