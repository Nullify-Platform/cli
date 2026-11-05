package scanfile

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func fakeAWSKey() string {
	return "AKIA" + "ABCDEFGHIJKLMNOP"
}

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

func TestScanContentMixedCaseFormatKeywords(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    []string
	}{
		{
			name:    "google",
			content: "AIza" + strings.Repeat("a", 35),
			want:    []string{"Hardcoded secret detected: Google API Key"},
		},
		{
			name:    "gemini",
			content: "AIzaSy" + strings.Repeat("a", 33),
			want: []string{
				"Hardcoded secret detected: Google Gemini API Key",
				"Hardcoded secret detected: Google API Key",
			},
		},
		{
			name:    "gcp-oauth",
			content: "GOCSPX-" + strings.Repeat("a", 28),
			want:    []string{"Hardcoded secret detected: GCP OAuth Client Secret"},
		},
		{
			name:    "onepassword",
			content: "ops_eyJ" + strings.Repeat("a", 200),
			want:    []string{"Hardcoded secret detected: Onepassword Service Account Token"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := ScanContent([]byte(tt.content), "config.txt", "")
			got := make([]string, 0, len(findings))
			for _, f := range findings {
				got = append(got, f.Message)
			}
			require.Equal(t, tt.want, got)
		})
	}
}

func TestScanContentQuotedCredentialKeys(t *testing.T) {
	key := "f3Kq9vXz2Lm8Wp4Rb7Nt"
	uuid := "7d9b6c5a-42ef-4b03-a981-6f0c3258de74"
	tests := []struct {
		name    string
		content string
		want    []string
	}{
		{
			name:    "generic-assignment",
			content: `password = "` + key + `"`,
			want:    []string{"Hardcoded secret detected: Generic API Key"},
		},
		{
			name:    "generic-json",
			content: `{"password": "` + key + `"}`,
			want:    []string{"Hardcoded secret detected: Generic API Key"},
		},
		{
			name:    "generic-single-quotes",
			content: `{'api_key': '` + key + `'}`,
			want:    []string{"Hardcoded secret detected: Generic API Key"},
		},
		{
			name:    "aws-json",
			content: `{"aws_secret_access_key": "` + key + key + `"}`,
			want:    []string{"Hardcoded secret detected: AWS Secret Access Key"},
		},
		{
			name:    "heroku-json",
			content: `{"heroku_api_key": "` + uuid + `"}`,
			want: []string{
				"Hardcoded secret detected: Heroku API Key",
				"Hardcoded secret detected: Generic API Key",
			},
		},
		{
			name:    "cloudflare-json",
			content: `{"cloudflare_api_token": "` + key + key + `"}`,
			want: []string{
				"Hardcoded secret detected: Cloudflare API Token",
				"Hardcoded secret detected: Generic API Key",
			},
		},
		{
			name:    "railway-json",
			content: `{"railway_api_token": "` + uuid + `"}`,
			want: []string{
				"Hardcoded secret detected: Railway API Token",
				"Hardcoded secret detected: Generic API Key",
			},
		},
		{
			name:    "postmark-json",
			content: `{"postmark_server_token": "` + uuid + `"}`,
			want: []string{
				"Hardcoded secret detected: Postmark Server Token",
				"Hardcoded secret detected: Generic API Key",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := ScanContent([]byte(tt.content), "config.txt", "")
			got := make([]string, 0, len(findings))
			for _, f := range findings {
				got = append(got, f.Message)
			}
			require.Equal(t, tt.want, got)
		})
	}
}

func TestScanContentUTF16InclusiveColumns(t *testing.T) {
	tests := []struct {
		name      string
		prefix    string
		wantStart int
		wantEnd   int
	}{
		{name: "ascii", prefix: `value = "`, wantStart: 10, wantEnd: 29},
		{name: "bmp", prefix: `é = "`, wantStart: 6, wantEnd: 25},
		{name: "surrogate-pair", prefix: `😀é = "`, wantStart: 8, wantEnd: 27},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			content := "\r\n" + tt.prefix + fakeAWSKey() + "\"\r\n"
			findings := ScanContent([]byte(content), "config.txt", "")
			require.Len(t, findings, 1)
			require.Equal(t, 2, findings[0].StartLine)
			require.Equal(t, 2, findings[0].EndLine)
			require.Equal(t, tt.wantStart, findings[0].StartColumn)
			require.Equal(t, tt.wantEnd, findings[0].EndColumn)
		})
	}
}

func TestScanContentPEMHeaderSpan(t *testing.T) {
	for _, kind := range []string{"", "RSA ", "EC ", "DSA ", "OPENSSH ", "PGP "} {
		t.Run(kind, func(t *testing.T) {
			header := "-----BEGIN " + kind + "PRIVATE KEY-----"
			findings := ScanContent([]byte(header), "key.pem", "")
			require.Len(t, findings, 1)
			require.Equal(t, 1, findings[0].StartColumn)
			require.Equal(t, len(header), findings[0].EndColumn)
			require.Equal(t, "Hardcoded secret detected: PEM Private Key", findings[0].Message)
		})
	}
}

func TestScanContentMultilineDeepSeek(t *testing.T) {
	secret := "sk-" + strings.Repeat("0123456789abcdef", 2)
	tests := []struct {
		name      string
		content   string
		wantLine  int
		wantCount int
	}{
		{name: "same-line", content: "deepseek " + secret, wantLine: 1, wantCount: 1},
		{name: "next-line", content: "deepseek\n" + secret, wantLine: 2, wantCount: 1},
		{name: "crlf", content: "deepseek\r\n" + secret, wantLine: 2, wantCount: 1},
		{name: "too-far", content: "deepseek" + strings.Repeat(" ", 41) + secret, wantCount: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := ScanContent([]byte(tt.content), "config.txt", "")
			require.Len(t, findings, tt.wantCount)
			if tt.wantCount == 0 {
				return
			}
			require.Equal(t, "Hardcoded secret detected: Deepseek API Key", findings[0].Message)
			require.Equal(t, tt.wantLine, findings[0].StartLine)
			require.Equal(t, tt.wantLine, findings[0].EndLine)
			require.Equal(t, 35, findings[0].EndColumn-findings[0].StartColumn+1)
		})
	}
}

func TestScanContentPreservesLineScopedKeywords(t *testing.T) {
	content := "twilio\nSK" + strings.Repeat("a", 32)
	findings := ScanContent([]byte(content), "config.txt", "")
	require.Empty(t, findings)
}

func TestScanContentLimitsEarliestFindings(t *testing.T) {
	content := fakeAWSKey() + "\n" + strings.Repeat(fakeAnthropicKey()+"\n", 201)
	findings := ScanContent([]byte(content), "config.txt", "")

	require.Len(t, findings, 200)
	require.Equal(t, "Hardcoded secret detected: AWS Access Key ID", findings[0].Message)
	for i, f := range findings {
		require.Equal(t, i+1, f.StartLine)
	}
}
