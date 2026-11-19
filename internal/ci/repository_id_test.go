package ci

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// repositoryIDEnvs are every env var a provider reads for the repository ID.
var repositoryIDEnvs = []string{
	"GITHUB_REPOSITORY_ID", "CI_PROJECT_ID", "BITBUCKET_REPO_UUID",
	"BUILD_REPOSITORY_ID", "BUILD_REPOSITORY_PROVIDER",
}

func TestDetectRepositoryID(t *testing.T) {
	cases := []struct {
		name string
		env  map[string]string
		want RepositoryID
		ok   bool
	}{
		{
			name: "github actions",
			env:  map[string]string{"GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY_ID": "123456"},
			want: RepositoryID{Provider: GitProviderGitHub, ID: "123456", Source: "GITHUB_REPOSITORY_ID"},
			ok:   true,
		},
		{
			name: "github actions without the id",
			env:  map[string]string{"GITHUB_ACTIONS": "true"},
		},
		{
			name: "gitlab ci",
			env:  map[string]string{"GITLAB_CI": "true", "CI_PROJECT_ID": "77"},
			want: RepositoryID{Provider: GitProviderGitLab, ID: "77", Source: "CI_PROJECT_ID"},
			ok:   true,
		},
		{
			name: "bitbucket pipelines drops the uuid braces",
			env:  map[string]string{"BITBUCKET_BUILD_NUMBER": "5", "BITBUCKET_REPO_UUID": "{0f1e2d3c-aaaa-bbbb-cccc-0123456789ab}"},
			want: RepositoryID{Provider: GitProviderBitbucket, ID: "0f1e2d3c-aaaa-bbbb-cccc-0123456789ab", Source: "BITBUCKET_REPO_UUID"},
			ok:   true,
		},
		{
			name: "azure pipelines on an azure repo",
			env:  map[string]string{"TF_BUILD": "True", "BUILD_REPOSITORY_PROVIDER": "TfsGit", "BUILD_REPOSITORY_ID": "5d3c1b2a-1111-2222-3333-444455556666"},
			want: RepositoryID{Provider: GitProviderAzure, ID: "5d3c1b2a-1111-2222-3333-444455556666", Source: "BUILD_REPOSITORY_ID"},
			ok:   true,
		},
		{
			name: "azure pipelines on a github repo names no azure id",
			env:  map[string]string{"TF_BUILD": "True", "BUILD_REPOSITORY_PROVIDER": "GitHub", "BUILD_REPOSITORY_ID": "acme/widget"},
		},
		{
			name: "jenkins exposes no repository id",
			env:  map[string]string{"JENKINS_URL": "https://ci"},
		},
		{
			name: "a local run exposes no repository id",
			env:  map[string]string{"GITHUB_REPOSITORY_ID": "123456"},
		},
		{
			name: "a blank id is no id",
			env:  map[string]string{"GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY_ID": "  "},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			clearSignatureEnvs(t)
			for _, k := range repositoryIDEnvs {
				t.Setenv(k, "")
			}
			for k, v := range c.env {
				t.Setenv(k, v)
			}

			got, ok := DetectRepositoryID(Default())

			require.Equal(t, c.ok, ok)
			require.Equal(t, c.want, got)
		})
	}
}
