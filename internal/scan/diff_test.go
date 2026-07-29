package scan

import (
	"sort"
	"testing"

	"github.com/nullify-platform/cli/internal/scan/manifest"
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
