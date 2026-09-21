// Package scanfile implements the local, in-process secret scan behind
// `nullify secrets scan-file`: the IDE on-save scanner
// (ide/nullify-vscode in the Nullify monorepo) shells out to exactly this
// command, piping the buffer on stdin and expecting a JSON array of
// NormalizedFinding on stdout. File contents never leave the machine and no
// Nullify API call is made.
//
// This is a hand-written, from-scratch detector, not a port of the
// monorepo's internal `secrets/internal/scanners/gitleaks` engine. That
// engine wraps github.com/zricethezav/gitleaks/v8 (MIT licensed, and
// otherwise a clean dependency), but importing its `detect`/`sources`
// packages unconditionally compiles in a WASM regex runtime
// (tetratelabs/wazero + wasilibs/go-re2, present for an opt-in build tag),
// a full archive/decompression stack for git-history and archive scanning
// (mholt/archives: 7z/rar/brotli/lzip/xz/zstd, plus their own sub-trees),
// and a terminal-styling/TUI toolkit (charmbracelet/lipgloss and its
// dependents) used only by gitleaks' own CLI report rendering. None of that
// is exercised by a single-file/stdin scan, but Go still needs the whole
// dependency closure resolvable — on the order of 60-90 additional
// transitive modules in this publicly distributed binary, none of them
// internal to Nullify, all reused from this session's own dependency
// analysis rather than blind guesses, but too large to hand-verify without
// a networked `go mod tidy` and a real build. See the PR description for
// the full breakdown.
//
// So this package reuses what is cleanly and safely reusable — Nullify's
// own custom detection rules (nullifyRules in rules.go, ported verbatim
// from secrets/internal/scanners/gitleaks/nullify-config.go, which has no
// engine dependency of its own) and the same entropy/placeholder
// false-positive filtering (rules.go) — plus a curated baseline of
// well-known public secret formats (baselineRules in rules.go) not already
// covered by Nullify's custom set, matched with the standard library's
// regexp package. It adds zero new third-party dependencies.
package scanfile

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
)

const (
	detectorClassSecret       = "Secret"
	cweHardcodedCredentials   = "CWE-798"
	severityHigh              = "high"
	messagePrefix             = "Hardcoded secret detected: "
	maxFindingsPerFileDefault = 200
)

// NormalizedFinding is the only shape the IDE extension ever sees. Lines and
// columns are 1-based (the platform/SARIF convention); the extension
// converts to its own 0-based coordinates. This mirrors
// secrets/internal/scanfile.NormalizedFinding field-for-field (including
// JSON casing) so ide/nullify-vscode's parsing needs no changes.
type NormalizedFinding struct {
	DetectorClass string `json:"detectorClass"`
	Severity      string `json:"severity"`
	File          string `json:"file"`
	StartLine     int    `json:"startLine"`
	EndLine       int    `json:"endLine"`
	StartColumn   int    `json:"startColumn"`
	EndColumn     int    `json:"endColumn"`
	CWE           string `json:"cwe"`
	Message       string `json:"message"`
	// Fingerprint is meant to correlate an on-save finding with a known
	// platform finding, mirroring the platform's secrets dedup key: a hash
	// over repository, file, start line and a secret-type label. The hash
	// SCHEME matches secrets/internal/scanfile's; the secret-type VALUES do
	// not, because this package's rule set is independently maintained from
	// the platform's internal gitleaks rules.csv classification. Exact
	// cross-correlation with pre-existing platform findings is therefore
	// not guaranteed — see the PR description.
	Fingerprint string `json:"fingerprint"`
}

// ScanContent scans content (a whole file, or an unsaved editor buffer that
// may differ from what is on disk) for hardcoded secrets. filePath labels
// each finding and drives the lockfile skip; repository is folded into the
// correlation fingerprint and may be empty.
func ScanContent(content []byte, filePath string, repository string) []NormalizedFinding {
	findings := make([]NormalizedFinding, 0)
	if isLockfilePath(filePath) {
		return findings
	}

	lines := strings.Split(string(content), "\n")

	for lineIdx, line := range lines {
		lower := strings.ToLower(line)
		for _, rule := range rules() {
			if !keywordsPresent(lower, rule.Keywords) {
				continue
			}

			for _, match := range rule.Regex.FindAllStringSubmatchIndex(line, -1) {
				startByte, endByte := secretSpan(match)
				secret := line[startByte:endByte]

				if isTestOrPlaceholder(secret) {
					continue
				}
				if rule.MinEntropy > 0 && !isHighConfidenceSecret(secret) && shannonEntropy(secret) < rule.MinEntropy {
					continue
				}

				findings = append(findings, NormalizedFinding{
					DetectorClass: detectorClassSecret,
					Severity:      severityHigh,
					File:          filePath,
					StartLine:     lineIdx + 1,
					EndLine:       lineIdx + 1,
					StartColumn:   startByte + 1,
					EndColumn:     endByte + 1,
					CWE:           cweHardcodedCredentials,
					Message:       messagePrefix + rule.Title(),
					Fingerprint:   fingerprint(repository, filePath, lineIdx+1, rule.Title()),
				})

				if len(findings) >= maxFindingsPerFileDefault {
					return findings
				}
			}
		}
	}

	return findings
}

// secretSpan picks the byte range to treat as "the secret" out of a
// FindAllStringSubmatchIndex match: the first capturing group that
// participated (rules that isolate the credential in a group, e.g. a regex
// anchored on surrounding punctuation or a `key = "..."` assignment), or the
// whole match when the rule has no capturing group or none of them fired for
// this particular alternation branch. This keeps entropy/placeholder checks
// — and the reported column range — scoped to the credential itself rather
// than including fixed keyword/punctuation text around it.
func secretSpan(match []int) (start, end int) {
	for i := 2; i+1 < len(match); i += 2 {
		if match[i] >= 0 && match[i+1] >= 0 {
			return match[i], match[i+1]
		}
	}
	return match[0], match[1]
}

// keywordsPresent reports whether lowerLine contains any of the rule's
// keywords. A rule with no keywords always runs (it has no cheap prefilter).
func keywordsPresent(lowerLine string, keywords []string) bool {
	if len(keywords) == 0 {
		return true
	}
	for _, kw := range keywords {
		if strings.Contains(lowerLine, kw) {
			return true
		}
	}
	return false
}

// fingerprint mirrors the platform's secrets dedup key: a hash over
// repository, file, start line and a secret-type label.
func fingerprint(repository, file string, startLine int, secretType string) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{
		"secret",
		repository,
		file,
		strconv.Itoa(startLine),
		secretType,
	}, "\x00")))
	return hex.EncodeToString(sum[:])
}
