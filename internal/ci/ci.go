// Package ci detects the CI/CD platform the CLI is currently running under
// and exposes the base/head commit refs it needs to compute changed
// dependencies.
//
// Implementations are registered in priority order in registry.go.
// Detect() returns the first provider whose env-var signature matches;
// the Local fallback is last so an unrecognised CI still works off
// `git rev-parse` defaults.
//
// Each provider reports a Platform value from the locally-defined set of
// constants below. When adding a provider, define its constant here and
// return it from Platform().
package ci

import (
	"context"
	"errors"
	"net/http"
)

// Platform is the canonical identifier for a CI/CD platform. Values are
// stamped onto the X-Nullify-CI-Provider header so scpm's audit log can
// attribute a CLI run to its CI environment.
type Platform string

const (
	PlatformGitHubActions      Platform = "GITHUB_ACTIONS"
	PlatformGitLabCI           Platform = "GITLAB_CI"
	PlatformCircleCI           Platform = "CIRCLECI"
	PlatformBitbucketPipelines Platform = "BITBUCKET_PIPELINES"
	PlatformJenkins            Platform = "JENKINS"
	PlatformAzureDevOps        Platform = "AZURE_DEVOPS"
	PlatformGoogleCloudBuild   Platform = "GOOGLE_CLOUD_BUILD"
	PlatformAWSCodeBuild       Platform = "AWS_CODEBUILD"
	PlatformOther              Platform = "OTHER"
)

func (p Platform) String() string { return string(p) }

// Provider identifies one CI/CD platform and exposes the information
// the CLI's deps-analyze + containers-analyze workflows need. All
// methods are expected to be cheap — provider detection happens on
// every CLI invocation.
type Provider interface {
	// Platform returns this provider's Platform constant.
	Platform() Platform

	// Detect returns true when the current process env matches this
	// provider's signature. Detect MUST NOT touch the network or
	// filesystem — env var inspection only.
	Detect() bool

	// BaseRef returns the commit or ref (short sha, full sha, or
	// branch name) the CI declared as the base of the current build,
	// resolved against the git repository at repoPath. For PR builds,
	// this is the PR target branch's HEAD at PR open time; for push
	// builds, it's the previous HEAD of the pushed branch. Fall back to
	// "origin/<default-branch>" when CI doesn't expose a specific base.
	BaseRef(ctx context.Context, repoPath string) (string, error)

	// HeadRef returns the commit the current build is running against,
	// resolved against the git repository at repoPath. For PR builds,
	// this is the PR's head commit; for push builds, the pushed commit.
	HeadRef(ctx context.Context, repoPath string) (string, error)

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
