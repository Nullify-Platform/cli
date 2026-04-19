package ci

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// GitHubActions — https://docs.github.com/en/actions/learn-github-actions/variables
//
// Key envs we rely on:
//   GITHUB_ACTIONS=true       signature
//   GITHUB_SHA                head commit
//   GITHUB_EVENT_NAME=pull_request  + GITHUB_BASE_REF (target branch name)
//   GITHUB_REPOSITORY         owner/name
//   GITHUB_RUN_ID + GITHUB_RUN_ATTEMPT
//
// PR base is tricky: GITHUB_BASE_REF is just the target branch NAME, not
// a commit. BaseRef() resolves it by running `git rev-parse
// origin/<base>` which assumes the runner fetched origin (the standard
// actions/checkout@v4 does).
type GitHubActions struct{}

func NewGitHubActions() Provider { return &GitHubActions{} }

func (g *GitHubActions) Platform() string { return "GITHUB_ACTIONS" }

func (g *GitHubActions) Detect() bool { return os.Getenv("GITHUB_ACTIONS") == "true" }

func (g *GitHubActions) BaseRef(ctx context.Context) (string, error) {
	// PR build: GITHUB_BASE_REF is populated; resolve to commit.
	if base := os.Getenv("GITHUB_BASE_REF"); base != "" {
		return resolveRef(ctx, "origin/"+base)
	}
	// Push build: use the previous commit on the pushed ref (HEAD^).
	// Falls back to the default branch's tip when HEAD has no parent
	// (first push).
	if sha, err := resolveRef(ctx, "HEAD^"); err == nil {
		return sha, nil
	}
	return resolveRef(ctx, "origin/HEAD")
}

func (g *GitHubActions) HeadRef(ctx context.Context) (string, error) {
	if sha := os.Getenv("GITHUB_SHA"); sha != "" {
		return sha, nil
	}
	return resolveRef(ctx, "HEAD")
}

func (g *GitHubActions) PRNumber() (int, bool) {
	ref := os.Getenv("GITHUB_REF")
	// Shape: "refs/pull/123/merge" for PR builds.
	if !strings.HasPrefix(ref, "refs/pull/") {
		return 0, false
	}
	parts := strings.Split(ref, "/")
	if len(parts) < 3 {
		return 0, false
	}
	n, err := strconv.Atoi(parts[2])
	if err != nil {
		return 0, false
	}
	return n, true
}

func (g *GitHubActions) RepoSlug() (string, string, bool) {
	repo := os.Getenv("GITHUB_REPOSITORY")
	if repo == "" {
		return "", "", false
	}
	parts := strings.SplitN(repo, "/", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	return parts[0], parts[1], true
}

func (g *GitHubActions) EnrichHeader(h http.Header) {
	if v := os.Getenv("GITHUB_RUN_ID"); v != "" {
		h.Set("X-Nullify-CI-Run-ID", v)
	}
	if v := os.Getenv("GITHUB_SHA"); v != "" {
		h.Set("X-Nullify-CI-Commit", v)
	}
	h.Set("X-Nullify-CI-Provider", g.Platform())
}

// resolveRef runs `git rev-parse` to turn a symbolic ref into a commit.
// Package-level helper so every provider reuses the same shell-out.
func resolveRef(ctx context.Context, ref string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", "rev-parse", "--verify", ref+"^{commit}")
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("git rev-parse %s: %w", ref, err)
	}
	return strings.TrimSpace(string(out)), nil
}
