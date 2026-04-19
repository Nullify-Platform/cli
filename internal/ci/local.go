package ci

import (
	"context"
	"net/http"
	"os"
)

// Local is the fallback when no CI env vars match — useful when
// developers run `nullify deps analyze` on their laptop before pushing.
// Always returns true from Detect(), so it MUST be the last entry in
// the registry list.
//
// Defaults:
//   BaseRef = origin/HEAD (the remote's default-branch tip)
//   HeadRef = HEAD
//
// Operators can override either via NULLIFY_BASE_REF / NULLIFY_HEAD_REF
// env vars if their local-dev workflow needs something specific.
type Local struct{}

func NewLocal() Provider { return &Local{} }

func (l *Local) Platform() string { return "OTHER" }

func (l *Local) Detect() bool { return true }

func (l *Local) BaseRef(ctx context.Context) (string, error) {
	if v := os.Getenv("NULLIFY_BASE_REF"); v != "" {
		return resolveRef(ctx, v)
	}
	return resolveRef(ctx, "origin/HEAD")
}

func (l *Local) HeadRef(ctx context.Context) (string, error) {
	if v := os.Getenv("NULLIFY_HEAD_REF"); v != "" {
		return resolveRef(ctx, v)
	}
	return resolveRef(ctx, "HEAD")
}

func (l *Local) PRNumber() (int, bool) {
	return 0, false
}

func (l *Local) RepoSlug() (string, string, bool) {
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

func (l *Local) EnrichHeader(h http.Header) {
	h.Set("X-Nullify-CI-Provider", l.Platform())
}
