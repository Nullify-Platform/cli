package ci

import (
	"os"
	"strings"
)

// GitProvider names the git hosting service that a repository ID belongs to.
type GitProvider string

const (
	GitProviderGitHub    GitProvider = "github"
	GitProviderGitLab    GitProvider = "gitlab"
	GitProviderBitbucket GitProvider = "bitbucket"
	GitProviderAzure     GitProvider = "azure"
)

// RepositoryID is the git provider's ID of the repository a CI build runs
// for. Nullify stores findings against this ID, so it scopes a finding query
// to the repository exactly, where a name could match a repository with the
// same name under another owner.
type RepositoryID struct {
	Provider GitProvider
	ID       string
	// Source names the environment variable the ID was read from.
	Source string
}

// RepositoryIdentifier is implemented by the providers whose environment
// names the repository's ID at its git provider.
type RepositoryIdentifier interface {
	RepositoryID() (RepositoryID, bool)
}

// DetectRepositoryID returns the repository ID that the detected CI platform
// exposes. It reports false when no provider matches, or when the matching
// provider exposes no repository ID.
func DetectRepositoryID(providers []Provider) (RepositoryID, bool) {
	provider, err := Detect(providers)
	if err != nil {
		return RepositoryID{}, false
	}
	identifier, ok := provider.(RepositoryIdentifier)
	if !ok {
		return RepositoryID{}, false
	}
	return identifier.RepositoryID()
}

// repositoryIDFromEnv reads a repository ID from one environment variable.
// Bitbucket writes its UUID in braces and Nullify stores it without them, so
// the braces are dropped.
func repositoryIDFromEnv(provider GitProvider, name string) (RepositoryID, bool) {
	value := strings.Trim(strings.TrimSpace(os.Getenv(name)), "{}")
	if value == "" {
		return RepositoryID{}, false
	}
	return RepositoryID{Provider: provider, ID: value, Source: name}, true
}

// RepositoryID returns GITHUB_REPOSITORY_ID, the numeric GitHub repository ID.
func (g *GitHubActions) RepositoryID() (RepositoryID, bool) {
	return repositoryIDFromEnv(GitProviderGitHub, "GITHUB_REPOSITORY_ID")
}

// RepositoryID returns CI_PROJECT_ID, the numeric GitLab project ID.
func (g *GitLabCI) RepositoryID() (RepositoryID, bool) {
	return repositoryIDFromEnv(GitProviderGitLab, "CI_PROJECT_ID")
}

// RepositoryID returns BITBUCKET_REPO_UUID without its braces.
func (b *BitbucketPipelines) RepositoryID() (RepositoryID, bool) {
	return repositoryIDFromEnv(GitProviderBitbucket, "BITBUCKET_REPO_UUID")
}

// RepositoryID returns BUILD_REPOSITORY_ID for an Azure Repos repository.
// Azure Pipelines also builds GitHub and Bitbucket repositories, and there
// the variable holds the repository's name rather than an Azure ID.
func (a *AzureDevOps) RepositoryID() (RepositoryID, bool) {
	if os.Getenv("BUILD_REPOSITORY_PROVIDER") != "TfsGit" {
		return RepositoryID{}, false
	}
	return repositoryIDFromEnv(GitProviderAzure, "BUILD_REPOSITORY_ID")
}
