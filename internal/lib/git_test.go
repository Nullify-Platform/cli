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
