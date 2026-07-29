package manifest

import (
	"testing"
)

// entriesEqual compares two Entry slices ignoring order — parsers that
// iterate maps (npm) don't guarantee a stable order.
func entriesEqual(t *testing.T, got, want []Entry) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("entry count = %d, want %d\ngot:  %+v\nwant: %+v", len(got), len(want), got, want)
	}
	index := func(es []Entry) map[string]Entry {
		m := map[string]Entry{}
		for _, e := range es {
			m[string(e.Ecosystem)+"|"+e.Name+"|"+e.Version] = e
		}
		return m
	}
	gi, wi := index(got), index(want)
	for k, w := range wi {
		g, ok := gi[k]
		if !ok {
			t.Fatalf("missing entry %q\ngot: %+v", k, got)
		}
		if g != w {
			t.Fatalf("entry %q = %+v, want %+v", k, g, w)
		}
	}
}

func TestNPMLock(t *testing.T) {
	// lockfileVersion 3 packages map: scoped, nested node_modules, empty
	// root, and a missing-version entry that must be skipped.
	data := []byte(`{
	  "lockfileVersion": 3,
	  "packages": {
	    "": {"name": "root", "version": "1.0.0"},
	    "node_modules/lodash": {"version": "4.17.21"},
	    "node_modules/@scope/pkg": {"version": "2.0.0"},
	    "node_modules/a/node_modules/lodash": {"version": "3.0.0"},
	    "node_modules/noversion": {"dev": true}
	  }
	}`)
	got, err := NewNPMLock().Parse(data, "package-lock.json")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	entriesEqual(t, got, []Entry{
		{Ecosystem: EcosystemNPM, Name: "lodash", Version: "4.17.21", File: "package-lock.json"},
		{Ecosystem: EcosystemNPM, Name: "@scope/pkg", Version: "2.0.0", File: "package-lock.json"},
		// nested node_modules/a/node_modules/lodash → "lodash" @ 3.0.0
		{Ecosystem: EcosystemNPM, Name: "lodash", Version: "3.0.0", File: "package-lock.json"},
	})
}

func TestNPMLock_InvalidJSON(t *testing.T) {
	if _, err := NewNPMLock().Parse([]byte("{not json"), "package-lock.json"); err == nil {
		t.Fatal("expected error on invalid JSON")
	}
}

func TestPyPILock(t *testing.T) {
	data := []byte(`# a comment
requests==2.32.3
flask == 3.0.0  # inline comment
django==4.2.11; python_version >= "3.8"
requests[security]==2.31.0
numpy==1.26.4 --hash=sha256:abc
-r other.txt
-e .
git+https://github.com/foo/bar.git
https://example.com/pkg.whl
uvicorn~=0.29
blank-name==
==1.2.3
`)
	got, err := NewPyPILock().Parse(data, "requirements.txt")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	entriesEqual(t, got, []Entry{
		{Ecosystem: EcosystemPyPI, Name: "requests", Version: "2.32.3", File: "requirements.txt", Direct: true},
		{Ecosystem: EcosystemPyPI, Name: "flask", Version: "3.0.0", File: "requirements.txt", Direct: true},
		{Ecosystem: EcosystemPyPI, Name: "django", Version: "4.2.11", File: "requirements.txt", Direct: true},
		{Ecosystem: EcosystemPyPI, Name: "requests", Version: "2.31.0", File: "requirements.txt", Direct: true},
		{Ecosystem: EcosystemPyPI, Name: "numpy", Version: "1.26.4", File: "requirements.txt", Direct: true},
	})
}

func TestGoSum(t *testing.T) {
	// go.sum: dedupe (zip + /go.mod rows), skip /go.mod-only rows.
	data := []byte(`github.com/foo/bar v1.2.3 h1:abc=
github.com/foo/bar v1.2.3/go.mod h1:def=
github.com/baz/qux v0.1.0/go.mod h1:ghi=
github.com/baz/qux v0.1.0 h1:jkl=
golang.org/x/sys v0.18.0 h1:mno=
`)
	got, err := NewGoMod().Parse(data, "go.sum")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	entriesEqual(t, got, []Entry{
		{Ecosystem: EcosystemGo, Name: "github.com/foo/bar", Version: "v1.2.3", File: "go.sum"},
		{Ecosystem: EcosystemGo, Name: "github.com/baz/qux", Version: "v0.1.0", File: "go.sum"},
		{Ecosystem: EcosystemGo, Name: "golang.org/x/sys", Version: "v0.18.0", File: "go.sum"},
	})
}

func TestCargoLock(t *testing.T) {
	// Workspace member (no source) must be skipped; registry crates kept.
	data := []byte(`# auto-generated
[[package]]
name = "my-app"
version = "0.1.0"

[[package]]
name = "serde"
version = "1.0.197"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "tokio"
version = "1.36.0"
source = "registry+https://github.com/rust-lang/crates.io-index"

[metadata]
foo = "bar"
`)
	got, err := NewCargoLock().Parse(data, "Cargo.lock")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	entriesEqual(t, got, []Entry{
		{Ecosystem: EcosystemCargo, Name: "serde", Version: "1.0.197", File: "Cargo.lock"},
		{Ecosystem: EcosystemCargo, Name: "tokio", Version: "1.36.0", File: "Cargo.lock"},
	})
}

func TestGemfileLock(t *testing.T) {
	// Only indent-4 spec lines under GEM/specs:; indent-6 transitive
	// declarations are skipped.
	data := []byte("GEM\n" +
		"  remote: https://rubygems.org/\n" +
		"  specs:\n" +
		"    activerecord (7.1.3)\n" +
		"      activemodel (= 7.1.3)\n" +
		"      activesupport (= 7.1.3)\n" +
		"    i18n (1.14.1)\n" +
		"      concurrent-ruby (~> 1.0)\n" +
		"PLATFORMS\n" +
		"  x86_64-linux\n" +
		"DEPENDENCIES\n" +
		"  rails\n")
	got, err := NewGemfileLock().Parse(data, "Gemfile.lock")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	entriesEqual(t, got, []Entry{
		{Ecosystem: EcosystemRubyGems, Name: "activerecord", Version: "7.1.3", File: "Gemfile.lock"},
		{Ecosystem: EcosystemRubyGems, Name: "i18n", Version: "1.14.1", File: "Gemfile.lock"},
	})
}

func TestMatches(t *testing.T) {
	cases := []struct {
		parser Parser
		path   string
		want   bool
	}{
		{NewNPMLock(), "frontend/package-lock.json", true},
		{NewNPMLock(), "package.json", false},
		{NewPyPILock(), "requirements.txt", true},
		{NewPyPILock(), "requirements-dev.txt", true},
		{NewGoMod(), "go.sum", true},
		{NewGoMod(), "go.mod", false},
		{NewCargoLock(), "Cargo.lock", true},
		{NewGemfileLock(), "Gemfile.lock", true},
	}
	for _, c := range cases {
		if got := c.parser.Matches(c.path); got != c.want {
			t.Errorf("%s.Matches(%q) = %v, want %v", c.parser.Name(), c.path, got, c.want)
		}
	}
}

func TestParseAll_FirstMatchWins(t *testing.T) {
	files := []File{
		{Path: "go.sum", Data: []byte("github.com/foo/bar v1.0.0 h1:x=\n")},
		{Path: "README.md", Data: []byte("# not a lockfile")},
	}
	res := ParseAll(DefaultParsers(), files)
	if len(res.Entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(res.Entries))
	}
	if len(res.Errors) != 0 {
		t.Fatalf("errors = %v, want none", res.Errors)
	}
}
