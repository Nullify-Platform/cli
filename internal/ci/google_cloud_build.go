package ci

import (
	"context"
	"net/http"
	"os"
)

// GoogleCloudBuild — https://cloud.google.com/build/docs/configuring-builds/substitute-variable-values
//
// GCB's predefined substitutions are prefixed COMMIT_SHA, BUILD_ID,
// PROJECT_ID, REPO_NAME. When triggered via the GitHub mirror integration
// we also get _PR_NUMBER. No standard "target branch" variable — rely
// on NULLIFY_BASE_REF when running against PR diffs.
type GoogleCloudBuild struct{}

func NewGoogleCloudBuild() Provider { return &GoogleCloudBuild{} }

func (g *GoogleCloudBuild) Platform() Platform { return PlatformGoogleCloudBuild }

// Detect: Google Cloud Build doesn't expose a single CI=true-style flag;
// BUILD_ID + PROJECT_ID together are a reasonable signature.
func (g *GoogleCloudBuild) Detect() bool {
	return os.Getenv("BUILD_ID") != "" && os.Getenv("PROJECT_ID") != "" &&
		os.Getenv("GITLAB_CI") == "" && os.Getenv("GITHUB_ACTIONS") != "true"
}

func (g *GoogleCloudBuild) BaseRef(ctx context.Context, repoPath string) (string, error) {
	if v := os.Getenv("NULLIFY_BASE_REF"); v != "" {
		return resolveRef(ctx, repoPath, v)
	}
	return resolveRef(ctx, repoPath, "origin/HEAD")
}

func (g *GoogleCloudBuild) HeadRef(ctx context.Context, repoPath string) (string, error) {
	if v := os.Getenv("COMMIT_SHA"); v != "" {
		return v, nil
	}
	return resolveRef(ctx, repoPath, "HEAD")
}

func (g *GoogleCloudBuild) PRNumber() (int, bool) {
	// Not exposed by GCB in a standard way; operators can set
	// NULLIFY_PR_NUMBER if their trigger template plumbs it.
	return 0, false
}

func (g *GoogleCloudBuild) RepoSlug() (string, string, bool) {
	owner := os.Getenv("PROJECT_ID")
	name := os.Getenv("REPO_NAME")
	if owner == "" || name == "" {
		return "", "", false
	}
	return owner, name, true
}

func (g *GoogleCloudBuild) EnrichHeader(h http.Header) {
	if v := os.Getenv("BUILD_ID"); v != "" {
		h.Set("X-Nullify-CI-Run-ID", v)
	}
	if v := os.Getenv("COMMIT_SHA"); v != "" {
		h.Set("X-Nullify-CI-Commit", v)
	}
	h.Set("X-Nullify-CI-Provider", g.Platform().String())
}
