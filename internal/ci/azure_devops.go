package ci

import (
	"context"
	"net/http"
	"os"
	"strconv"
)

// AzureDevOps — https://learn.microsoft.com/en-us/azure/devops/pipelines/build/variables
//
// Key envs:
//   TF_BUILD=True                            signature
//   BUILD_SOURCEVERSION                      head commit
//   SYSTEM_PULLREQUEST_TARGETBRANCHNAME      target branch (PR builds)
//   SYSTEM_PULLREQUEST_PULLREQUESTNUMBER     PR number
//   BUILD_REPOSITORY_NAME                    repo name (no owner)
//   BUILD_BUILDID                            run id
type AzureDevOps struct{}

func NewAzureDevOps() Provider { return &AzureDevOps{} }

func (a *AzureDevOps) Platform() string { return "AZURE_DEVOPS" }

func (a *AzureDevOps) Detect() bool { return os.Getenv("TF_BUILD") == "True" }

func (a *AzureDevOps) BaseRef(ctx context.Context) (string, error) {
	if v := os.Getenv("SYSTEM_PULLREQUEST_TARGETBRANCHNAME"); v != "" {
		return resolveRef(ctx, "origin/"+v)
	}
	return resolveRef(ctx, "HEAD^")
}

func (a *AzureDevOps) HeadRef(ctx context.Context) (string, error) {
	if v := os.Getenv("BUILD_SOURCEVERSION"); v != "" {
		return v, nil
	}
	return resolveRef(ctx, "HEAD")
}

func (a *AzureDevOps) PRNumber() (int, bool) {
	v := os.Getenv("SYSTEM_PULLREQUEST_PULLREQUESTNUMBER")
	if v == "" {
		return 0, false
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, false
	}
	return n, true
}

func (a *AzureDevOps) RepoSlug() (string, string, bool) {
	// Azure uses Organization/Project/Repo — not a two-part slug.
	// Collapse Organization as the "owner" field.
	owner := os.Getenv("SYSTEM_COLLECTIONURI")
	name := os.Getenv("BUILD_REPOSITORY_NAME")
	if name == "" {
		return "", "", false
	}
	return owner, name, true
}

func (a *AzureDevOps) EnrichHeader(h http.Header) {
	if v := os.Getenv("BUILD_BUILDID"); v != "" {
		h.Set("X-Nullify-CI-Run-ID", v)
	}
	if v := os.Getenv("BUILD_SOURCEVERSION"); v != "" {
		h.Set("X-Nullify-CI-Commit", v)
	}
	h.Set("X-Nullify-CI-Provider", a.Platform())
}
