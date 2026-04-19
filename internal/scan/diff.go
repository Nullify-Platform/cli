// Package scan orchestrates the CLI's "what changed between these
// two commits" logic. It wraps git ops, manifest parsing, and the
// set-difference that produces the (added, bumped, removed) lists
// deps-analyze consumes.
package scan

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/nullify-platform/cli/internal/scan/manifest"
)

// ChangedDep is one dependency whose (ecosystem, name, version) tuple
// changed between base and head. Kind distinguishes the three change
// modes so the workflow can prioritise "new version + bumped version"
// for analyze calls while skipping removals (removed deps don't have a
// new version to analyse).
type ChangedDep struct {
	Ecosystem       string
	Name            string
	Version         string
	PreviousVersion string // Empty for "added".
	Kind            string // "added" | "bumped" | "removed"
	File            string // Lockfile path change was detected in
}

// Diff compares two commits by reading their lockfiles via `git show`
// and diffing the parsed manifest entries. Returns the changed deps
// ordered by (file, name) for stable display.
func Diff(ctx context.Context, repoPath, baseRef, headRef string, parsers []manifest.Parser) ([]ChangedDep, error) {
	// List files changed between the two revs that are lockfiles we
	// know how to parse. Cheaper than reading every lockfile in the
	// repo for both revs — a monorepo can have hundreds.
	changedPaths, err := listChangedFiles(ctx, repoPath, baseRef, headRef)
	if err != nil {
		return nil, err
	}
	lockfilePaths := filterLockfiles(changedPaths, parsers)
	if len(lockfilePaths) == 0 {
		return nil, nil
	}

	baseEntries, err := parseAtRef(ctx, repoPath, baseRef, lockfilePaths, parsers)
	if err != nil {
		return nil, fmt.Errorf("parse base lockfiles: %w", err)
	}
	headEntries, err := parseAtRef(ctx, repoPath, headRef, lockfilePaths, parsers)
	if err != nil {
		return nil, fmt.Errorf("parse head lockfiles: %w", err)
	}

	return diffEntries(baseEntries, headEntries), nil
}

// listChangedFiles runs `git diff --name-only base..head`. Missing
// lockfiles (e.g., deleted at head) are still returned — the parser
// just produces zero entries for that rev.
func listChangedFiles(ctx context.Context, repoPath, base, head string) ([]string, error) {
	cmd := exec.CommandContext(ctx, "git", "diff", "--name-only", base+".."+head)
	cmd.Dir = repoPath
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git diff --name-only: %w", err)
	}
	var paths []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		paths = append(paths, line)
	}
	return paths, nil
}

func filterLockfiles(paths []string, parsers []manifest.Parser) []string {
	out := []string{}
	for _, p := range paths {
		for _, parser := range parsers {
			if parser.Matches(p) {
				out = append(out, p)
				break
			}
		}
	}
	return out
}

// parseAtRef does `git show <ref>:<path>` for each lockfile + feeds
// the bytes to the matching parser. Missing-at-this-ref is NOT an error
// — the file may have been added (not in base) or deleted (not in
// head); both are normal.
func parseAtRef(
	ctx context.Context,
	repoPath, ref string,
	paths []string,
	parsers []manifest.Parser,
) (map[entryKey]manifest.Entry, error) {
	files := make([]manifest.File, 0, len(paths))
	for _, p := range paths {
		data, err := gitShow(ctx, repoPath, ref, p)
		if err != nil {
			// File doesn't exist at this ref — skip silently.
			continue
		}
		files = append(files, manifest.File{Path: p, Data: data})
	}
	res := manifest.ParseAll(parsers, files)
	out := map[entryKey]manifest.Entry{}
	for _, e := range res.Entries {
		out[entryKey{Ecosystem: e.Ecosystem, Name: e.Name}] = e
	}
	return out, nil
}

type entryKey struct {
	Ecosystem string
	Name      string
}

// gitShow captures `git show <ref>:<path>`. Returns an error that
// callers treat as "file absent at this ref."
func gitShow(ctx context.Context, repoPath, ref, path string) ([]byte, error) {
	var stdout bytes.Buffer
	cmd := exec.CommandContext(ctx, "git", "show", ref+":"+path)
	cmd.Dir = repoPath
	cmd.Stdout = &stdout
	if err := cmd.Run(); err != nil {
		return nil, err
	}
	return stdout.Bytes(), nil
}

// diffEntries produces the (added, bumped, removed) set from the
// base→head entry maps. Keyed by (ecosystem, name) — so a package
// renamed mid-flight appears as one removed + one added entry, which
// is the right shape for analysis.
func diffEntries(base, head map[entryKey]manifest.Entry) []ChangedDep {
	out := []ChangedDep{}
	for k, headEntry := range head {
		baseEntry, existsInBase := base[k]
		switch {
		case !existsInBase:
			out = append(out, ChangedDep{
				Ecosystem: headEntry.Ecosystem,
				Name:      headEntry.Name,
				Version:   headEntry.Version,
				Kind:      "added",
				File:      headEntry.File,
			})
		case baseEntry.Version != headEntry.Version:
			out = append(out, ChangedDep{
				Ecosystem:       headEntry.Ecosystem,
				Name:            headEntry.Name,
				Version:         headEntry.Version,
				PreviousVersion: baseEntry.Version,
				Kind:            "bumped",
				File:            headEntry.File,
			})
		}
	}
	for k, baseEntry := range base {
		if _, stillInHead := head[k]; !stillInHead {
			out = append(out, ChangedDep{
				Ecosystem:       baseEntry.Ecosystem,
				Name:            baseEntry.Name,
				PreviousVersion: baseEntry.Version,
				Kind:            "removed",
				File:            baseEntry.File,
			})
		}
	}
	return out
}
