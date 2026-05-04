// Package ci detects the CI/CD platform the CLI is currently running under
// and exposes the base/head commit refs it needs to compute changed
// dependencies.
//
// Implementations are registered in priority order in registry.go.
// Detect() returns the first provider whose env-var signature matches;
// the Local fallback is last so an unrecognised CI still works off
// `git rev-parse` defaults.
//
// This package deliberately uses the PipelinePlatform enum from
// benchmarks/models — the canonical set of platforms Nullify supports
// lives there, and any new provider added to this package must have a
// matching enum value (lint check in cli/Makefile enforces this).
package ci

import (
	"context"
	"errors"
	"net/http"
)

// Provider identifies one CI/CD platform and exposes the information
// the CLI's deps-analyze + containers-analyze workflows need. All
// methods are expected to be cheap — provider detection happens on
// every CLI invocation.
type Provider interface {
	// Platform returns the canonical PipelinePlatform enum value (from
	// benchmarks/models). Must match the string in the Makefile's
	// provider-coverage lint target.
	Platform() string

	// Detect returns true when the current process env matches this
	// provider's signature. Detect MUST NOT touch the network or
	// filesystem — env var inspection only.
	Detect() bool

	// BaseRef returns the commit or ref (short sha, full sha, or
	// branch name) the CI declared as the base of the current build.
	// For PR builds, this is the PR target branch's HEAD at PR open
	// time; for push builds, it's the previous HEAD of the pushed
	// branch. Fall back to "origin/<default-branch>" when CI doesn't
	// expose a specific base.
	BaseRef(ctx context.Context) (string, error)

	// HeadRef returns the commit the current build is running against.
	// For PR builds, this is the PR's head commit; for push builds,
	// the pushed commit.
	HeadRef(ctx context.Context) (string, error)

	// PRNumber returns the pull-request number if the current build is
	// a PR, and (0, false) otherwise. Used for diagnostic logging + as
	// the idempotency-key prefix in scpm calls.
	PRNumber() (int, bool)

	// RepoSlug returns (owner, name) for GitHub/GitLab/Bitbucket-style
	// coordinates. Returns (_, _, false) when the provider doesn't
	// expose it (eg. Jenkins, self-hosted CI).
	RepoSlug() (owner, name string, ok bool)

	// EnrichHeader adds CI-specific headers to outbound HTTP requests
	// (commit SHA, PR number, run ID) so scpm's audit log can tie a
	// specific CLI run back to a CI invocation. Called once per HTTP
	// request built by the workflow.
	EnrichHeader(h http.Header)
}

// ErrNoProvider is returned by Detect when no registered provider
// matches — shouldn't happen in practice because the Local fallback
// always returns true, but declared so callers can assert on it.
var ErrNoProvider = errors.New("no CI provider detected")
