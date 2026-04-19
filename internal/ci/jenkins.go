package ci

import (
	"context"
	"net/http"
	"os"
	"strconv"
)

// Jenkins — https://www.jenkins.io/doc/book/pipeline/jenkinsfile/#using-environment-variables
//
// Jenkins has no canonical "target branch" variable — different pipeline
// setups expose different things. We read the common Multibranch /
// GitHub-branch-source envs + fall back to NULLIFY_BASE_REF for anything
// the operator prefers to set by hand.
//
// Key envs:
//   JENKINS_URL                     signature
//   GIT_COMMIT                      head
//   CHANGE_ID                       PR number (Multibranch)
//   CHANGE_TARGET                   PR target branch
//   BUILD_NUMBER                    run id
type Jenkins struct{}

func NewJenkins() Provider { return &Jenkins{} }

func (j *Jenkins) Platform() string { return "JENKINS" }

func (j *Jenkins) Detect() bool { return os.Getenv("JENKINS_URL") != "" }

func (j *Jenkins) BaseRef(ctx context.Context) (string, error) {
	if v := os.Getenv("NULLIFY_BASE_REF"); v != "" {
		return resolveRef(ctx, v)
	}
	if v := os.Getenv("CHANGE_TARGET"); v != "" {
		return resolveRef(ctx, "origin/"+v)
	}
	return resolveRef(ctx, "origin/HEAD")
}

func (j *Jenkins) HeadRef(ctx context.Context) (string, error) {
	if v := os.Getenv("GIT_COMMIT"); v != "" {
		return v, nil
	}
	return resolveRef(ctx, "HEAD")
}

func (j *Jenkins) PRNumber() (int, bool) {
	v := os.Getenv("CHANGE_ID")
	if v == "" {
		return 0, false
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, false
	}
	return n, true
}

func (j *Jenkins) RepoSlug() (string, string, bool) {
	// Jenkins doesn't expose owner/name directly — an operator-provided
	// NULLIFY_REPO_SLUG=owner/name covers the case. Without it we
	// return (_, _, false) and scpm falls back to other identifying
	// headers.
	slug := os.Getenv("NULLIFY_REPO_SLUG")
	if slug == "" {
		return "", "", false
	}
	for i := range slug {
		if slug[i] == '/' {
			return slug[:i], slug[i+1:], true
		}
	}
	return "", "", false
}

func (j *Jenkins) EnrichHeader(h http.Header) {
	if v := os.Getenv("BUILD_NUMBER"); v != "" {
		h.Set("X-Nullify-CI-Run-ID", v)
	}
	if v := os.Getenv("GIT_COMMIT"); v != "" {
		h.Set("X-Nullify-CI-Commit", v)
	}
	h.Set("X-Nullify-CI-Provider", j.Platform())
}
