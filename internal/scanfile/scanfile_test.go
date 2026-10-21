package scanfile

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// fakeAWSKey builds an AWS-access-key-ID-shaped fixture (AKIA + 16 chars
// from [A-Z2-7], distinct from the well-known AWS docs example key that this
// package's placeholder filter deliberately allowlists) via concatenation,
// so the 20-character string never appears contiguous in this file's own
// source text and can't trip a secret scanner on this repo's own commits.
func fakeAWSKey() string {
	return "AKIA" + "ABCDEFGHIJKLMNOP"
}

// fakeAnthropicKey builds an Anthropic-key-shaped fixture the same way.
func fakeAnthropicKey() string {
	return "sk-ant-api03-" + strings.Repeat("x", 93) + "AA"
}

func TestScanContentDetectsBaselineRule(t *testing.T) {
	content := []byte("awsKey := \"" + fakeAWSKey() + "\"\n")

	findings := ScanContent(content, "config.go", "")
	require.NotEmpty(t, findings)

	f := findings[0]
	require.Equal(t, detectorClassSecret, f.DetectorClass)
	require.Equal(t, cweHardcodedCredentials, f.CWE)
	require.Equal(t, "config.go", f.File)
	require.Equal(t, 1, f.StartLine)
	require.Equal(t, "Hardcoded secret detected: AWS Access Key ID", f.Message)
	require.NotEmpty(t, f.Fingerprint)
}

func TestScanContentDetectsNullifyCustomRule(t *testing.T) {
	key := fakeAnthropicKey()
	content := []byte("const anthropicKey = \"" + key + "\"\n")

	findings := ScanContent(content, "main.go", "")
	require.NotEmpty(t, findings)
	require.Equal(t, "Hardcoded secret detected: Anthropic API Key", findings[0].Message)
}

func TestScanContentCleanBufferHasNoFindings(t *testing.T) {
	findings := ScanContent([]byte("package main\n\nfunc main() {}\n"), "main.go", "")
	require.Empty(t, findings)
}

func TestScanContentFiltersPlaceholderValues(t *testing.T) {
	content := []byte(`apiKey = "your-api-key-here"` + "\n")
	findings := ScanContent(content, "config.go", "")
	require.Empty(t, findings, "placeholder values must never be reported")
}

func TestScanContentFiltersLowEntropyGenericValues(t *testing.T) {
	content := []byte(`password = "aaaaaaaaaaaaaaaa"` + "\n")
	findings := ScanContent(content, "config.go", "")
	require.Empty(t, findings, "low-entropy generic assignments must be filtered")
}

func TestScanContentSkipsLockfiles(t *testing.T) {
	// A value that would otherwise trip the AWS access key rule.
	content := []byte("\"" + fakeAWSKey() + "\"\n")
	findings := ScanContent(content, "nested/dir/package-lock.json", "")
	require.Empty(t, findings, "lockfiles must be skipped entirely")
}

func TestScanContentNeverLeaksTheSecretValue(t *testing.T) {
	key := fakeAnthropicKey()
	content := []byte("const anthropicKey = \"" + key + "\"\n")

	findings := ScanContent(content, "main.go", "")
	require.NotEmpty(t, findings)
	for _, f := range findings {
		require.NotContains(t, f.Message, key)
		require.NotContains(t, f.Fingerprint, key)
	}
}

// The fingerprint must stay a hash over {"secret", repository, file,
// startLine, Title} or on-save findings stop correlating across repeated
// scans of the same file.
func TestFingerprintScheme(t *testing.T) {
	content := []byte("awsKey := \"" + fakeAWSKey() + "\"\n")
	findings := ScanContent(content, "config.go", "owner/repo")
	require.NotEmpty(t, findings)
	f := findings[0]

	want := fingerprint("owner/repo", "config.go", f.StartLine, "AWS Access Key ID")
	require.Equal(t, want, f.Fingerprint)
}

func TestRuleTitleFormatsKnownAcronyms(t *testing.T) {
	r := Rule{ID: "aws-access-key-id"}
	require.Equal(t, "AWS Access Key ID", r.Title())

	r = Rule{ID: "generic-api-key"}
	require.Equal(t, "Generic API Key", r.Title())
}

func TestAllRulesCompileAndHaveUniqueIDs(t *testing.T) {
	seen := map[string]bool{}
	for _, r := range rules() {
		require.NotNil(t, r.Regex, "rule %q must have a compiled regex", r.ID)
		require.False(t, seen[r.ID], "duplicate rule id %q", r.ID)
		seen[r.ID] = true
	}
	require.NotEmpty(t, rules())
}

func TestShannonEntropy(t *testing.T) {
	require.InDelta(t, 0.0, shannonEntropy("aaaaaaaa"), 0.001)
	require.Greater(t, shannonEntropy("f3Kq9vXz2Lm8Wp4Rb7Nt"), 3.5)
}

func TestIsLockfilePath(t *testing.T) {
	require.True(t, isLockfilePath("package-lock.json"))
	require.True(t, isLockfilePath("nested/dir/go.sum"))
	require.False(t, isLockfilePath("main.go"))
}

func TestFingerprintIsDeterministic(t *testing.T) {
	a := fingerprint("owner/repo", "file.go", 4, "Generic API Key")
	b := fingerprint("owner/repo", "file.go", 4, "Generic API Key")
	require.Equal(t, a, b)

	c := fingerprint("owner/repo", "file.go", 5, "Generic API Key")
	require.NotEqual(t, a, c)
}
