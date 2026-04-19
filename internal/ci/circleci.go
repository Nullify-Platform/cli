package ci

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
)

// CircleCI — https://circleci.com/docs/variables/
//
// Key envs:
//   CIRCLECI=true
//   CIRCLE_SHA1                     head
//   CIRCLE_PR_NUMBER                PR number (only when triggered from a
//                                   forked-PR webhook)
//   CIRCLE_PULL_REQUEST             "https://github.com/org/repo/pull/N"
//                                   — parse to recover the PR number
//                                   for non-forked PRs too
//   CIRCLE_PROJECT_USERNAME/REPONAME
//   CIRCLE_WORKFLOW_ID              run id
type CircleCI struct{}

func NewCircleCI() Provider { return &CircleCI{} }

func (c *CircleCI) Platform() string { return "CIRCLECI" }

func (c *CircleCI) Detect() bool { return os.Getenv("CIRCLECI") == "true" }

func (c *CircleCI) BaseRef(ctx context.Context) (string, error) {
	// Circle doesn't expose a base commit directly. Best available:
	// origin/<default-branch>. Callers wanting PR-diff semantics should
	// set NULLIFY_BASE_REF explicitly.
	if v := os.Getenv("NULLIFY_BASE_REF"); v != "" {
		return resolveRef(ctx, v)
	}
	return resolveRef(ctx, "origin/HEAD")
}

func (c *CircleCI) HeadRef(ctx context.Context) (string, error) {
	if v := os.Getenv("CIRCLE_SHA1"); v != "" {
		return v, nil
	}
	return resolveRef(ctx, "HEAD")
}

func (c *CircleCI) PRNumber() (int, bool) {
	if v := os.Getenv("CIRCLE_PR_NUMBER"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n, true
		}
	}
	if v := os.Getenv("CIRCLE_PULL_REQUEST"); v != "" {
		// Parse "https://github.com/org/repo/pull/123".
		parts := strings.Split(v, "/")
		if len(parts) >= 2 && parts[len(parts)-2] == "pull" {
			if n, err := strconv.Atoi(parts[len(parts)-1]); err == nil {
				return n, true
			}
		}
	}
	return 0, false
}

func (c *CircleCI) RepoSlug() (string, string, bool) {
	owner := os.Getenv("CIRCLE_PROJECT_USERNAME")
	name := os.Getenv("CIRCLE_PROJECT_REPONAME")
	if owner == "" || name == "" {
		return "", "", false
	}
	return owner, name, true
}

func (c *CircleCI) EnrichHeader(h http.Header) {
	if v := os.Getenv("CIRCLE_WORKFLOW_ID"); v != "" {
		h.Set("X-Nullify-CI-Run-ID", v)
	}
	if v := os.Getenv("CIRCLE_SHA1"); v != "" {
		h.Set("X-Nullify-CI-Commit", v)
	}
	h.Set("X-Nullify-CI-Provider", c.Platform())
}

// _ is a tiny type guard that keeps fmt imported for future error-wrapping
// additions without a noisy linter warning in the meantime.
var _ = fmt.Sprintf
