package ci

import (
	"context"
	"net/http"
	"os"
	"strconv"
)

// BitbucketPipelines — https://support.atlassian.com/bitbucket-cloud/docs/variables-and-secrets/
//
// Key envs:
//   BITBUCKET_BUILD_NUMBER          signature
//   BITBUCKET_COMMIT                head
//   BITBUCKET_PR_DESTINATION_BRANCH target branch (PR builds)
//   BITBUCKET_PR_ID                 PR number
//   BITBUCKET_REPO_OWNER / REPO_SLUG
type BitbucketPipelines struct{}

func NewBitbucketPipelines() Provider { return &BitbucketPipelines{} }

func (b *BitbucketPipelines) Platform() string { return "BITBUCKET_PIPELINES" }

func (b *BitbucketPipelines) Detect() bool {
	return os.Getenv("BITBUCKET_BUILD_NUMBER") != ""
}

func (b *BitbucketPipelines) BaseRef(ctx context.Context) (string, error) {
	if v := os.Getenv("BITBUCKET_PR_DESTINATION_BRANCH"); v != "" {
		return resolveRef(ctx, "origin/"+v)
	}
	return resolveRef(ctx, "HEAD^")
}

func (b *BitbucketPipelines) HeadRef(ctx context.Context) (string, error) {
	if v := os.Getenv("BITBUCKET_COMMIT"); v != "" {
		return v, nil
	}
	return resolveRef(ctx, "HEAD")
}

func (b *BitbucketPipelines) PRNumber() (int, bool) {
	v := os.Getenv("BITBUCKET_PR_ID")
	if v == "" {
		return 0, false
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, false
	}
	return n, true
}

func (b *BitbucketPipelines) RepoSlug() (string, string, bool) {
	owner := os.Getenv("BITBUCKET_REPO_OWNER")
	name := os.Getenv("BITBUCKET_REPO_SLUG")
	if owner == "" || name == "" {
		return "", "", false
	}
	return owner, name, true
}

func (b *BitbucketPipelines) EnrichHeader(h http.Header) {
	if v := os.Getenv("BITBUCKET_BUILD_NUMBER"); v != "" {
		h.Set("X-Nullify-CI-Run-ID", v)
	}
	if v := os.Getenv("BITBUCKET_COMMIT"); v != "" {
		h.Set("X-Nullify-CI-Commit", v)
	}
	h.Set("X-Nullify-CI-Provider", b.Platform())
}
