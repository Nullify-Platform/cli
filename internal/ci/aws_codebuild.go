package ci

import (
	"context"
	"net/http"
	"os"
	"strings"
)

// AWSCodeBuild — https://docs.aws.amazon.com/codebuild/latest/userguide/build-env-ref-env-vars.html
//
// Key envs:
//   CODEBUILD_BUILD_ID              signature
//   CODEBUILD_RESOLVED_SOURCE_VERSION  head
//   CODEBUILD_WEBHOOK_BASE_REF      base (webhook-triggered PRs)
//   CODEBUILD_SOURCE_REPO_URL       https://github.com/org/repo.git
type AWSCodeBuild struct{}

func NewAWSCodeBuild() Provider { return &AWSCodeBuild{} }

func (a *AWSCodeBuild) Platform() string { return "AWS_CODEBUILD" }

func (a *AWSCodeBuild) Detect() bool { return os.Getenv("CODEBUILD_BUILD_ID") != "" }

func (a *AWSCodeBuild) BaseRef(ctx context.Context) (string, error) {
	// CODEBUILD_WEBHOOK_BASE_REF is "refs/heads/main" shape — strip the
	// prefix + resolve.
	if v := os.Getenv("CODEBUILD_WEBHOOK_BASE_REF"); v != "" {
		return resolveRef(ctx, "origin/"+strings.TrimPrefix(v, "refs/heads/"))
	}
	return resolveRef(ctx, "origin/HEAD")
}

func (a *AWSCodeBuild) HeadRef(ctx context.Context) (string, error) {
	if v := os.Getenv("CODEBUILD_RESOLVED_SOURCE_VERSION"); v != "" {
		return v, nil
	}
	return resolveRef(ctx, "HEAD")
}

func (a *AWSCodeBuild) PRNumber() (int, bool) {
	// CODEBUILD_WEBHOOK_TRIGGER sometimes has "pr/123" shape.
	trigger := os.Getenv("CODEBUILD_WEBHOOK_TRIGGER")
	if !strings.HasPrefix(trigger, "pr/") {
		return 0, false
	}
	n := 0
	for _, c := range trigger[3:] {
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int(c-'0')
	}
	return n, true
}

func (a *AWSCodeBuild) RepoSlug() (string, string, bool) {
	repoURL := os.Getenv("CODEBUILD_SOURCE_REPO_URL")
	if repoURL == "" {
		return "", "", false
	}
	// Strip trailing .git + any protocol; keep the final "owner/name"
	// segment.
	trimmed := strings.TrimSuffix(repoURL, ".git")
	parts := strings.Split(trimmed, "/")
	if len(parts) < 2 {
		return "", "", false
	}
	return parts[len(parts)-2], parts[len(parts)-1], true
}

func (a *AWSCodeBuild) EnrichHeader(h http.Header) {
	if v := os.Getenv("CODEBUILD_BUILD_ID"); v != "" {
		h.Set("X-Nullify-CI-Run-ID", v)
	}
	if v := os.Getenv("CODEBUILD_RESOLVED_SOURCE_VERSION"); v != "" {
		h.Set("X-Nullify-CI-Commit", v)
	}
	h.Set("X-Nullify-CI-Provider", a.Platform())
}
