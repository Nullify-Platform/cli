package ci

import (
	"context"
	"net/http"
	"os"
	"strconv"
	"strings"
)

// GitLabCI — https://docs.gitlab.com/ci/variables/predefined_variables.html
//
// Key envs:
//   GITLAB_CI=true
//   CI_COMMIT_SHA                   head
//   CI_MERGE_REQUEST_TARGET_BRANCH_SHA   base (MR builds)
//   CI_COMMIT_BEFORE_SHA            base (push builds)
//   CI_MERGE_REQUEST_IID            PR number
//   CI_PROJECT_PATH                 owner/name
//   CI_PIPELINE_ID                  run id
type GitLabCI struct{}

func NewGitLabCI() Provider { return &GitLabCI{} }

func (g *GitLabCI) Platform() string { return "GITLAB_CI" }

func (g *GitLabCI) Detect() bool { return os.Getenv("GITLAB_CI") == "true" }

func (g *GitLabCI) BaseRef(ctx context.Context) (string, error) {
	// MR build preferred (exact PR target sha)
	if v := os.Getenv("CI_MERGE_REQUEST_TARGET_BRANCH_SHA"); v != "" {
		return v, nil
	}
	// Push build: BEFORE_SHA can be "0000..." on first push to a new
	// branch — treat that as "use default branch tip" instead.
	if v := os.Getenv("CI_COMMIT_BEFORE_SHA"); v != "" && !strings.HasPrefix(v, "00000000") {
		return v, nil
	}
	return resolveRef(ctx, "origin/HEAD")
}

func (g *GitLabCI) HeadRef(ctx context.Context) (string, error) {
	if v := os.Getenv("CI_COMMIT_SHA"); v != "" {
		return v, nil
	}
	return resolveRef(ctx, "HEAD")
}

func (g *GitLabCI) PRNumber() (int, bool) {
	v := os.Getenv("CI_MERGE_REQUEST_IID")
	if v == "" {
		return 0, false
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, false
	}
	return n, true
}

func (g *GitLabCI) RepoSlug() (string, string, bool) {
	v := os.Getenv("CI_PROJECT_PATH")
	if v == "" {
		return "", "", false
	}
	// GitLab allows nested groups (foo/bar/baz). Collapse all but the
	// last segment into the "owner" field so owner/name stays
	// well-formed.
	idx := strings.LastIndex(v, "/")
	if idx < 0 {
		return "", "", false
	}
	return v[:idx], v[idx+1:], true
}

func (g *GitLabCI) EnrichHeader(h http.Header) {
	if v := os.Getenv("CI_PIPELINE_ID"); v != "" {
		h.Set("X-Nullify-CI-Run-ID", v)
	}
	if v := os.Getenv("CI_COMMIT_SHA"); v != "" {
		h.Set("X-Nullify-CI-Commit", v)
	}
	h.Set("X-Nullify-CI-Provider", g.Platform())
}
