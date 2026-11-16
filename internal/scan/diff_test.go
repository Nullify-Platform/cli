package scan

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/nullify-platform/cli/internal/lib"
	"github.com/nullify-platform/cli/internal/scan/manifest"
	"github.com/stretchr/testify/require"
)

func mkMap(entries ...manifest.Entry) map[entryKey]manifest.Entry {
	m := map[entryKey]manifest.Entry{}
	for _, e := range entries {
		m[entryKey{Ecosystem: e.Ecosystem, Name: e.Name}] = e
	}
	return m
}

func TestDiffEntries(t *testing.T) {
	base := mkMap(
		manifest.Entry{Ecosystem: manifest.EcosystemNPM, Name: "stable", Version: "1.0.0", File: "package-lock.json"},
		manifest.Entry{Ecosystem: manifest.EcosystemNPM, Name: "bumped", Version: "1.0.0", File: "package-lock.json"},
		manifest.Entry{Ecosystem: manifest.EcosystemNPM, Name: "removed", Version: "1.0.0", File: "package-lock.json"},
	)
	head := mkMap(
		manifest.Entry{Ecosystem: manifest.EcosystemNPM, Name: "stable", Version: "1.0.0", File: "package-lock.json"},
		manifest.Entry{Ecosystem: manifest.EcosystemNPM, Name: "bumped", Version: "2.0.0", File: "package-lock.json"},
		manifest.Entry{Ecosystem: manifest.EcosystemNPM, Name: "added", Version: "0.1.0", File: "package-lock.json"},
	)

	got := diffEntries(base, head)
	sort.Slice(got, func(i, j int) bool { return got[i].Name < got[j].Name })

	want := []ChangedDep{
		{Ecosystem: manifest.EcosystemNPM, Name: "added", Version: "0.1.0", Kind: KindAdded, File: "package-lock.json"},
		{Ecosystem: manifest.EcosystemNPM, Name: "bumped", Version: "2.0.0", PreviousVersion: "1.0.0", Kind: KindBumped, File: "package-lock.json"},
		{Ecosystem: manifest.EcosystemNPM, Name: "removed", PreviousVersion: "1.0.0", Kind: KindRemoved, File: "package-lock.json"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d changes, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("change[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestDiffEntries_NoChange(t *testing.T) {
	m := mkMap(manifest.Entry{Ecosystem: manifest.EcosystemGo, Name: "x", Version: "v1.0.0"})
	if got := diffEntries(m, m); len(got) != 0 {
		t.Fatalf("expected no changes, got %+v", got)
	}
}

func TestGitRevisionBoundaries(t *testing.T) {
	ctx := context.Background()
	repo := t.TempDir()
	git := func(args ...string) string {
		t.Helper()
		cmd := exec.CommandContext(ctx, "git", args...)
		cmd.Dir = repo
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, "%s", out)
		return strings.TrimSpace(string(out))
	}
	git("init", "--initial-branch=main")
	git("config", "user.email", "test@example.com")
	git("config", "user.name", "Test")
	git("config", "commit.gpgsign", "false")
	path := "-lock.txt"
	require.NoError(t, os.WriteFile(filepath.Join(repo, path), []byte("base\n"), 0600))
	git("add", "--", path)
	git("commit", "-m", "base")
	base := git("rev-parse", "HEAD")
	require.NoError(t, os.WriteFile(filepath.Join(repo, path), []byte("head\n"), 0600))
	git("commit", "-am", "head")
	head := git("rev-parse", "HEAD")

	for _, tt := range []struct{ name, base, head, content string }{
		{"sha", base, head, "head\n"},
		{"branch", "main~", "main", "head\n"},
		{"relative", "HEAD~", "HEAD", "head\n"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			paths, err := listChangedFiles(ctx, repo, tt.base, tt.head)
			require.NoError(t, err)
			require.Equal(t, []string{path}, paths)
			data, err := gitShow(ctx, repo, tt.head, path)
			require.NoError(t, err)
			require.Equal(t, tt.content, string(data))
		})
	}

	for _, tt := range []struct{ name, ref string }{
		{"help", "--help"}, {"short option", "-p"}, {"output option", "--output=unexpected"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := listChangedFiles(ctx, repo, tt.ref, "HEAD")
			require.ErrorIs(t, err, lib.ErrGitRefOption)
			_, err = listChangedFiles(ctx, repo, "HEAD~", tt.ref)
			require.ErrorIs(t, err, lib.ErrGitRefOption)
			_, err = gitShow(ctx, repo, tt.ref, path)
			require.ErrorIs(t, err, lib.ErrGitRefOption)
			_, err = parseAtRef(ctx, repo, tt.ref, []string{path}, nil)
			require.ErrorIs(t, err, lib.ErrGitRefOption)
			_, err = Diff(ctx, repo, "HEAD~", tt.ref, nil)
			require.ErrorIs(t, err, lib.ErrGitRefOption)
		})
	}
}
