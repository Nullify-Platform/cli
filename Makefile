.PHONY: build clean lint lint-go lint-docker fetch-spec generate-api command-surface unit cov

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
# `make generate-api` and `make command-surface`, and commit spec/ and the
# regenerated code. The spec-drift workflow does this on a schedule.
SPEC_REF ?= 1b9c3dd0cf497030de8646ae1b8e1f407d25e04a
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
	go run ./scripts/generate --spec $(SPEC_LOCAL) --output internal/api --cmd-output internal/commands

# command-surface checks the command tree against spec/command-surface.tsv and
# rewrites that snapshot. It fails on a command or flag that disappeared unless
# internal/commands/surface_decisions.go records the decision.
command-surface:
	go run ./scripts/commandsurface --write

unit:
	go test -v -skip TestIntegration ./...

cov:
	-go test -coverpkg=./... -coverprofile=coverage.txt -covermode count ./...
	-gocover-cobertura < coverage.txt > coverage.xml
	-go tool cover -html=coverage.txt -o coverage.html
	-go tool cover -func=coverage.txt
