package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/nullify-platform/cli/internal/ci"
	"github.com/spf13/cobra"
)

// Errors for a repository scope the gate and the report cannot use.
var (
	errNoRepositoryScope = errors.New(
		"cannot tell which repository to check: set --repository-id to the repository's ID at its git provider, " +
			"or pass --all-repositories to count every repository " +
			"(the ID is detected in GitHub Actions, GitLab CI, Bitbucket Pipelines and Azure Pipelines)",
	)
	errInvalidRepositoryID        = errors.New("invalid repository ID")
	errConflictingRepositoryScope = errors.New("--repository-id and --all-repositories cannot be used together")
)

// repositoryScope is the repository whose findings the gate and the report
// count, or every repository.
type repositoryScope struct {
	all bool
	// id is the repository's ID at its git provider.
	id string
	// source names where the ID came from: the flag or a CI variable.
	source string
	// providerParams are the query parameters that narrow a list route to
	// the repository on the server.
	providerParams []string
}

// providerParamNames maps a git provider to the request parameter that names
// one of its repositories. GitLab has none on the per-scanner routes.
var providerParamNames = map[ci.GitProvider]string{
	ci.GitProviderGitHub:    "githubRepositoryId",
	ci.GitProviderBitbucket: "bitbucketRepositoryId",
	ci.GitProviderAzure:     "azureRepositoryId",
}

// scopeFromFlags resolves the repository scope of a CI command from its
// flags and the CI platform it runs under.
func scopeFromFlags(cmd *cobra.Command) (repositoryScope, error) {
	id, _ := cmd.Flags().GetString("repository-id")
	all, _ := cmd.Flags().GetBool("all-repositories")
	detect := func() (ci.RepositoryID, bool) { return ci.DetectRepositoryID(ci.Default()) }
	return resolveRepositoryScope(id, cmd.Flags().Changed("repository-id"), all, detect)
}

// resolveRepositoryScope picks the scope: --all-repositories, then
// --repository-id, then the repository ID the CI platform exposes. With none
// of them it fails, rather than counting every repository's findings in one
// repository's pipeline.
func resolveRepositoryScope(
	id string,
	idSet bool,
	all bool,
	detect func() (ci.RepositoryID, bool),
) (repositoryScope, error) {
	switch {
	case all && idSet:
		return repositoryScope{}, errConflictingRepositoryScope
	case all:
		return repositoryScope{all: true}, nil
	case idSet:
		return explicitRepositoryScope(id)
	}
	if detected, ok := detect(); ok {
		return detectedRepositoryScope(detected)
	}
	return repositoryScope{}, errNoRepositoryScope
}

// explicitRepositoryScope reads --repository-id. The flag does not say which
// git provider the ID belongs to, so the ID is sent under every provider
// parameter it can be: GitHub IDs are numeric, Bitbucket and Azure IDs are
// UUIDs. The server reads only the parameter of the tenant's own provider.
// Any other value is rejected, because a repository name would match no
// finding and the gate would pass without checking anything.
func explicitRepositoryScope(value string) (repositoryScope, error) {
	id := normalizeRepositoryID(value)
	scope := repositoryScope{id: id, source: "--repository-id"}
	switch {
	case isUUID(id):
		scope.providerParams = []string{"bitbucketRepositoryId", id, "azureRepositoryId", id}
	case isNumericRepositoryID(id):
		scope.providerParams = []string{"githubRepositoryId", id}
	default:
		return repositoryScope{}, fmt.Errorf("%w for --repository-id %q: expected a positive numeric ID without leading zeros or a UUID", errInvalidRepositoryID, value)
	}
	return scope, nil
}

func detectedRepositoryScope(detected ci.RepositoryID) (repositoryScope, error) {
	scope := repositoryScope{id: normalizeRepositoryID(detected.ID), source: detected.Source}
	switch detected.Provider {
	case ci.GitProviderGitHub, ci.GitProviderGitLab:
		if !isNumericRepositoryID(scope.id) {
			return repositoryScope{}, fmt.Errorf("%w in %s: expected a positive numeric ID without leading zeros", errInvalidRepositoryID, detected.Source)
		}
	case ci.GitProviderBitbucket, ci.GitProviderAzure:
		if !isUUID(scope.id) {
			return repositoryScope{}, fmt.Errorf("%w in %s: expected a UUID", errInvalidRepositoryID, detected.Source)
		}
	default:
		return repositoryScope{}, fmt.Errorf("%w: unknown provider %q", errInvalidRepositoryID, detected.Provider)
	}
	if name, ok := providerParamNames[detected.Provider]; ok {
		scope.providerParams = []string{name, scope.id}
	}
	return scope, nil
}

// queryParams returns the parameters that narrow a scanner's list route to
// the repository. A scanner whose findings have no repository gets none.
func (s repositoryScope) queryParams(ep scannerEndpoint) []string {
	if s.all || !ep.hasRepository {
		return nil
	}
	params := slices.Clone(s.providerParams)
	if ep.supportsRepositoryIDs {
		params = append(params, "repositoryIds", s.id)
	}
	if len(params) == 0 {
		return nil
	}
	return params
}

// includes reports whether a finding belongs to the scope. The server does
// not narrow every route for every git provider, so the CLI checks each
// finding's repositoryId itself. A finding without one is included, so the
// gate never passes a finding it could not place.
func (s repositoryScope) includes(ep scannerEndpoint, finding json.RawMessage) bool {
	if s.all || !ep.hasRepository {
		return true
	}
	var fields struct {
		RepositoryID *string `json:"repositoryId"`
	}
	if err := json.Unmarshal(finding, &fields); err != nil || fields.RepositoryID == nil || *fields.RepositoryID == "" {
		return true
	}
	return strings.EqualFold(normalizeRepositoryID(*fields.RepositoryID), s.id)
}

// describe names the scope for the command's log.
func (s repositoryScope) describe() string {
	if s.all {
		return "every repository (--all-repositories)"
	}
	return fmt.Sprintf("repository %s (from %s)", s.id, s.source)
}

// normalizeRepositoryID trims spaces and the braces Bitbucket puts around
// its UUIDs.
func normalizeRepositoryID(value string) string {
	return strings.Trim(strings.TrimSpace(value), "{}")
}

func isNumericRepositoryID(value string) bool {
	if value == "" || value[0] < '1' || value[0] > '9' {
		return false
	}
	_, err := strconv.ParseInt(value, 10, 64)
	return err == nil
}

// isUUID reports a value in the 8-4-4-4-12 hex form that Bitbucket and Azure
// DevOps use for repository IDs.
func isUUID(value string) bool {
	groups := strings.Split(value, "-")
	lengths := []int{8, 4, 4, 4, 12}
	if len(groups) != len(lengths) {
		return false
	}
	for i, group := range groups {
		if len(group) != lengths[i] || strings.Trim(strings.ToLower(group), "0123456789abcdef") != "" {
			return false
		}
	}
	return true
}
