package lib

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestExtractRepoName(t *testing.T) {
	tests := []struct {
		name      string
		remoteURL string
		want      string
	}{
		{
			name:      "SSH format",
			remoteURL: "git@github.com:nullify-platform/cli.git",
			want:      "cli",
		},
		{
			name:      "SSH format without .git",
			remoteURL: "git@github.com:nullify-platform/cli",
			want:      "cli",
		},
		{
			name:      "HTTPS format",
			remoteURL: "https://github.com/nullify-platform/cli.git",
			want:      "cli",
		},
		{
			name:      "HTTPS format without .git",
			remoteURL: "https://github.com/nullify-platform/cli",
			want:      "cli",
		},
		{
			name:      "SSH with nested path",
			remoteURL: "git@github.com:org/subgroup/repo.git",
			want:      "repo",
		},
		{
			name:      "HTTPS with nested path",
			remoteURL: "https://gitlab.com/org/subgroup/repo.git",
			want:      "repo",
		},
		{
			name:      "just a name",
			remoteURL: "my-repo",
			want:      "my-repo",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractRepoName(tt.remoteURL)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestExtractRepoOwner(t *testing.T) {
	tests := []struct {
		name      string
		remoteURL string
		want      string
	}{
		{"GitHub SSH", "git@github.com:acme-web/api.git", "acme-web"},
		{"GitHub SSH without .git", "git@github.com:acme-payments/web", "acme-payments"},
		{"GitHub HTTPS", "https://github.com/nullify-platform/cli.git", "nullify-platform"},
		{"GitHub HTTPS with credentials", "https://x-access-token:abc@github.com/acme/repo.git", "acme"},
		{"ssh scheme", "ssh://git@github.com/acme/repo.git", "acme"},
		{"ssh scheme with port", "ssh://git@github.com:22/acme/repo.git", "acme"},
		{"GitLab nested group", "https://gitlab.com/group/subgroup/repo.git", "group"},
		{"Bitbucket HTTPS with user", "https://jane@bitbucket.org/workspace/repo.git", "workspace"},
		{"Azure DevOps HTTPS", "https://dev.azure.com/contoso/project/_git/repo", "contoso"},
		{"Azure DevOps SSH", "git@ssh.dev.azure.com:v3/contoso/project/repo", "contoso"},
		{"just a name", "my-repo", ""},
		{"local path", "/srv/git/repo.git", ""},
		{"host only", "https://github.com/", ""},
		{"owner without repo", "https://github.com/acme", ""},
		{"empty", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, ExtractRepoOwner(tt.remoteURL))
		})
	}
}

func TestParseRepoFromGitConfigStillReadsOrigin(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	config := "[core]\n\tbare = false\n[remote \"upstream\"]\n\turl = git@github.com:other/fork.git\n" +
		"[remote \"origin\"]\n\turl = git@github.com:acme/widgets.git\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n"
	require.NoError(t, os.WriteFile(path, []byte(config), 0600))

	require.Equal(t, "widgets", ParseRepoFromGitConfig(path))
	require.Equal(t, "acme", ExtractRepoOwner(originURL(path)))
}
