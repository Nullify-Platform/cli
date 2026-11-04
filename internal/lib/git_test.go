package lib

import (
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

func TestExtractRepoFullName(t *testing.T) {
	tests := []struct {
		name      string
		remoteURL string
		want      string
	}{
		{name: "SSH", remoteURL: "git@github.com:nullify-platform/cli.git", want: "nullify-platform/cli"},
		{name: "HTTPS", remoteURL: "https://github.com/nullify-platform/cli.git", want: "nullify-platform/cli"},
		{name: "HTTPS with a token", remoteURL: "https://x-access-token:abc@github.com/nullify-platform/cli", want: "nullify-platform/cli"},
		{name: "SSH URL", remoteURL: "ssh://git@github.com/nullify-platform/cli.git", want: "nullify-platform/cli"},
		{name: "nested GitLab group", remoteURL: "https://gitlab.com/group/sub/cli.git", want: "group/sub/cli"},
		{name: "no remote", remoteURL: "", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, ExtractRepoFullName(tt.remoteURL))
		})
	}
}
