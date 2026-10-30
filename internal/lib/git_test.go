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

// A globex-web checkout picks globex-web whether it is a plain clone, a
// linked worktree or a submodule: in the last two .git is a file naming the
// real git dir, and a worktree's remote lives in its main repository's config.
func TestDetectOwnerFromGitInWorktreesAndSubmodules(t *testing.T) {
	root := t.TempDir()
	writeConfig := func(dir, owner string) {
		require.NoError(t, os.MkdirAll(dir, 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "config"),
			[]byte("[remote \"origin\"]\n\turl = git@github.com:"+owner+"/app.git\n"), 0o600))
	}

	clone := filepath.Join(root, "clone")
	writeConfig(filepath.Join(clone, ".git"), "globex-web")

	main := filepath.Join(root, "main")
	writeConfig(filepath.Join(main, ".git"), "globex-web")
	wtGitDir := filepath.Join(main, ".git", "worktrees", "feature")
	require.NoError(t, os.MkdirAll(wtGitDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(wtGitDir, "commondir"), []byte("../..\n"), 0o600))
	worktree := filepath.Join(root, "feature")
	require.NoError(t, os.MkdirAll(worktree, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(worktree, ".git"), []byte("gitdir: "+wtGitDir+"\n"), 0o600))

	super := filepath.Join(root, "super")
	writeConfig(filepath.Join(super, ".git"), "globex-ops")
	writeConfig(filepath.Join(super, ".git", "modules", "sub"), "globex-web")
	sub := filepath.Join(super, "sub")
	require.NoError(t, os.MkdirAll(filepath.Join(sub, "pkg"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(sub, ".git"), []byte("gitdir: ../.git/modules/sub\n"), 0o600))

	for _, dir := range []string{clone, worktree, filepath.Join(sub, "pkg")} {
		t.Chdir(dir)
		require.Equal(t, "globex-web", DetectOwnerFromGit(), dir)
		require.Equal(t, "app", DetectRepoFromGit(), dir)
	}
}
