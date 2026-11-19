package cmd

import (
	"encoding/json"
	"testing"

	"github.com/nullify-platform/cli/internal/ci"
	"github.com/stretchr/testify/require"
)

func detected(provider ci.GitProvider, id, source string) func() (ci.RepositoryID, bool) {
	return func() (ci.RepositoryID, bool) {
		return ci.RepositoryID{Provider: provider, ID: id, Source: source}, true
	}
}

func notDetected() (ci.RepositoryID, bool) { return ci.RepositoryID{}, false }

func TestResolveRepositoryScope(t *testing.T) {
	tests := []struct {
		name    string
		id      string
		all     bool
		detect  func() (ci.RepositoryID, bool)
		want    repositoryScope
		wantErr error
	}{
		{
			name:   "a numeric id is a GitHub id",
			id:     "42",
			detect: notDetected,
			want:   repositoryScope{id: "42", source: "--repository-id", providerParams: []string{"githubRepositoryId", "42"}},
		},
		{
			name:   "a uuid may be a Bitbucket or an Azure id",
			id:     " {0f1e2d3c-aaaa} ",
			detect: notDetected,
			want: repositoryScope{
				id: "0f1e2d3c-aaaa", source: "--repository-id",
				providerParams: []string{"bitbucketRepositoryId", "0f1e2d3c-aaaa", "azureRepositoryId", "0f1e2d3c-aaaa"},
			},
		},
		{
			name:   "the flag wins over the CI platform",
			id:     "42",
			detect: detected(ci.GitProviderGitHub, "7", "GITHUB_REPOSITORY_ID"),
			want:   repositoryScope{id: "42", source: "--repository-id", providerParams: []string{"githubRepositoryId", "42"}},
		},
		{
			name:   "github actions",
			detect: detected(ci.GitProviderGitHub, "7", "GITHUB_REPOSITORY_ID"),
			want:   repositoryScope{id: "7", source: "GITHUB_REPOSITORY_ID", providerParams: []string{"githubRepositoryId", "7"}},
		},
		{
			name:   "gitlab ci has no provider parameter",
			detect: detected(ci.GitProviderGitLab, "77", "CI_PROJECT_ID"),
			want:   repositoryScope{id: "77", source: "CI_PROJECT_ID"},
		},
		{
			name:   "bitbucket pipelines",
			detect: detected(ci.GitProviderBitbucket, "abc", "BITBUCKET_REPO_UUID"),
			want:   repositoryScope{id: "abc", source: "BITBUCKET_REPO_UUID", providerParams: []string{"bitbucketRepositoryId", "abc"}},
		},
		{
			name:   "azure pipelines",
			detect: detected(ci.GitProviderAzure, "guid", "BUILD_REPOSITORY_ID"),
			want:   repositoryScope{id: "guid", source: "BUILD_REPOSITORY_ID", providerParams: []string{"azureRepositoryId", "guid"}},
		},
		{
			name:   "every repository",
			all:    true,
			detect: detected(ci.GitProviderGitHub, "7", "GITHUB_REPOSITORY_ID"),
			want:   repositoryScope{all: true},
		},
		{name: "no repository", detect: notDetected, wantErr: errNoRepositoryScope},
		{name: "a blank id", id: "  ", detect: notDetected, wantErr: errInvalidRepositoryID},
		{name: "a numeric id too large for any provider", id: "99999999999999999999", detect: notDetected, wantErr: errInvalidRepositoryID},
		{name: "both an id and every repository", id: "42", all: true, detect: notDetected, wantErr: errConflictingRepositoryScope},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolveRepositoryScope(tt.id, tt.id != "", tt.all, tt.detect)

			require.ErrorIs(t, err, tt.wantErr)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestRepositoryScopeQueryParams(t *testing.T) {
	scope := repositoryScope{id: "42", source: "--repository-id", providerParams: []string{"githubRepositoryId", "42"}}
	tests := []struct {
		scanner string
		scope   repositoryScope
		want    []string
	}{
		{"sast", scope, []string{"githubRepositoryId", "42", "repositoryIds", "42"}},
		{"sca_dependencies", scope, []string{"githubRepositoryId", "42"}},
		{"sca_containers", scope, []string{"githubRepositoryId", "42"}},
		{"secrets", scope, []string{"githubRepositoryId", "42"}},
		{"pentest", scope, nil},
		{"bughunt", scope, nil},
		{"cspm", scope, nil},
		{"sast", repositoryScope{id: "77", source: "CI_PROJECT_ID"}, []string{"repositoryIds", "77"}},
		{"secrets", repositoryScope{id: "77", source: "CI_PROJECT_ID"}, nil},
		{"sast", repositoryScope{all: true}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.scanner+" "+tt.scope.id, func(t *testing.T) {
			require.Equal(t, tt.want, tt.scope.queryParams(scannerByName(t, tt.scanner)))
		})
	}
}

func TestRepositoryScopeIncludes(t *testing.T) {
	scope := repositoryScope{id: "0f1e2d3c-aaaa", source: "--repository-id"}
	tests := []struct {
		name     string
		scanner  string
		scope    repositoryScope
		finding  string
		included bool
	}{
		{"the same repository", "sca_dependencies", scope, `{"repositoryId":"0f1e2d3c-aaaa"}`, true},
		{"the same id in another case and in braces", "secrets", scope, `{"repositoryId":"{0F1E2D3C-AAAA}"}`, true},
		{"another repository", "sast", scope, `{"repositoryId":"99"}`, false},
		{"a finding without a repository id counts", "sca_containers", scope, `{"id":"c1"}`, true},
		{"a finding that cannot be read counts", "sast", scope, `not json`, true},
		{"a cloud finding is never filtered", "cspm", scope, `{"repositoryId":"99"}`, true},
		{"a pentest finding is never filtered", "pentest", scope, `{"repositoryId":"99"}`, true},
		{"every repository", "sast", repositoryScope{all: true}, `{"repositoryId":"99"}`, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.scope.includes(scannerByName(t, tt.scanner), json.RawMessage(tt.finding))
			require.Equal(t, tt.included, got)
		})
	}
}
