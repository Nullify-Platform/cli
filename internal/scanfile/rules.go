package scanfile

import (
	"math"
	"regexp"
	"strings"
	"sync"
)

// Rule is a single hand-written secret-detection rule. It has no relation to
// gitleaks' rule shape (see the package doc for why). There is no explicit
// secret-group field: scanfile.secretSpan takes the first capturing group
// that participated in a match, falling back to the whole match for rules
// with no group, so a rule opts into scoping the reported secret just by
// wrapping it in parentheses.
type Rule struct {
	// ID is a short, stable slug. It never reaches the client directly; it
	// is only used to derive Title() and to key MinEntropy overrides.
	ID    string
	Regex *regexp.Regexp
	// Keywords is a cheap case-insensitive substring prefilter: if set, the
	// regex only runs on a line containing at least one keyword.
	Keywords []string
	// MinEntropy is the minimum Shannon entropy (bits/char) the matched text
	// must have to be reported, unless it also matches
	// highConfidenceSecretPatterns. Zero disables the check.
	MinEntropy float64
}

// acronyms upper-cases well-known abbreviations when deriving Title() from
// ID; every other hyphen-separated word is simply capitalized.
var acronyms = map[string]string{
	"aws": "AWS", "api": "API", "jwt": "JWT", "iam": "IAM", "cos": "COS",
	"hmac": "HMAC", "gcp": "GCP", "ibm": "IBM", "pat": "PAT", "id": "ID",
	"url": "URL", "npm": "NPM", "sql": "SQL", "pem": "PEM", "sdk": "SDK",
	"greenid": "GreenID", "oauth": "OAuth", "openai": "OpenAI", "xai": "xAI",
	"vixverify": "VixVerify",
}

// Title renders ID as a short, human-readable label, e.g. "aws-access-key-id"
// -> "AWS Access Key ID". It is what reaches the client, in the finding
// message and folded into the correlation fingerprint — never the raw ID or
// the regex/rule internals.
func (r Rule) Title() string {
	words := strings.Split(r.ID, "-")
	for i, w := range words {
		if up, ok := acronyms[strings.ToLower(w)]; ok {
			words[i] = up
			continue
		}
		if w == "" {
			continue
		}
		words[i] = strings.ToUpper(w[:1]) + w[1:]
	}
	return strings.Join(words, " ")
}

var rulesOnce = sync.OnceValue(func() []Rule {
	all := make([]Rule, 0, 64)
	all = append(all, nullifyRules()...)
	all = append(all, baselineRules()...)
	return all
})

// rules returns the combined, compiled rule table (Nullify's own custom
// rules plus the baseline well-known-format rules), built once.
func rules() []Rule {
	return rulesOnce()
}

// lockfileNames are dependency manifests that carry long hex/base64-looking
// integrity hashes that regularly trip entropy-based heuristics. Mirrors the
// allowlist secrets/internal/scanners/gitleaks/config.go builds for the same
// reason, minus the vendored-directory half (a single-file/stdin scan only
// ever sees the file currently open in the editor, not a vendored tree).
var lockfileNames = map[string]bool{
	"package-lock.json": true,
	"yarn.lock":         true,
	"pnpm-lock.yaml":    true,
	"Gemfile.lock":      true,
	"Cargo.lock":        true,
	"poetry.lock":       true,
	"go.sum":            true,
	"composer.lock":     true,
	"Pipfile.lock":      true,
}

func isLockfilePath(filePath string) bool {
	base := filePath
	if idx := strings.LastIndexAny(filePath, "/\\"); idx >= 0 {
		base = filePath[idx+1:]
	}
	return lockfileNames[base]
}

// testPlaceholderPatterns are test, example and placeholder values filtered
// out as false positives. Ported verbatim from
// secrets/internal/scanners/gitleaks/rules.go.
var testPlaceholderPatterns = []string{
	"AKIAIOSFODNN7EXAMPLE",
	"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	"your-api-key-here",
	"your_api_key_here",
	"your-secret-here",
	"your_secret_here",
	"insert-your-key",
	"insert_your_key",
	"api-key-goes-here",
	"api_key_goes_here",
	"replace-with-your-key",
	"replace_with_your_key",
	"xxx",
	"XXX",
	"xxxxxxxx",
	"XXXXXXXX",
	"placeholder",
	"PLACEHOLDER",
	// Connection-string template idioms: the basic-auth rule captures the
	// password segment of scheme://user:pass@host.
	"pass",
	"passwd",
	"user",
	"username",
	"password",
	"password123",
	"password1234",
	"test123",
	"test1234",
	"testtest",
	"changeme",
	"admin123",
	"secret123",
	"example",
	"sample",
	"dummy",
	"fake",
	"mock",
	"null",
	"undefined",
	"none",
	"empty",
	"todo",
	"fixme",
}

var templateVarPattern = regexp.MustCompile(`^<[a-z_]+>$`)

// highConfidenceSecretPatterns matches formats that are always real
// credentials and bypass entropy filtering; AWS access key IDs have low
// entropy (~3.2) but are never benign. The IAM unique-ID prefixes
// (AGPA/AIDA/AROA/AIPA/ANPA/ANVA) are excluded: they label non-secret
// identifiers. Ported verbatim from
// secrets/internal/scanners/gitleaks/rules.go.
var highConfidenceSecretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`^(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16}$`),
}

func isHighConfidenceSecret(secret string) bool {
	for _, pattern := range highConfidenceSecretPatterns {
		if pattern.MatchString(secret) {
			return true
		}
	}
	return false
}

func isTestOrPlaceholder(secret string) bool {
	lowerSecret := strings.ToLower(secret)

	for _, pattern := range testPlaceholderPatterns {
		if lowerSecret == strings.ToLower(pattern) {
			return true
		}
	}

	placeholderIndicators := []string{
		"example", "placeholder", "your-", "your_", "insert-", "insert_",
		"replace-", "replace_", "<your", "[your", "{your", "<api", "[api",
		"{api", "<secret", "[secret", "{secret", "<key", "[key", "{key",
		"<token", "[token", "{token", "todo", "fixme", "<redacted",
		"redacted", "hidden", "masked", "sanitized", "not_set", "${",
	}

	for _, indicator := range placeholderIndicators {
		if strings.Contains(lowerSecret, indicator) {
			return true
		}
	}

	return templateVarPattern.MatchString(lowerSecret)
}

// shannonEntropy returns the byte-frequency Shannon entropy of s, in
// bits/char. Same algorithm gitleaks' own entropy check and this package's
// MinEntropy thresholds are tuned against.
func shannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}

	var freq [256]float64
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}

	length := float64(len(s))
	var entropy float64
	for _, f := range freq {
		if f == 0 {
			continue
		}
		p := f / length
		entropy -= p * math.Log2(p)
	}
	return entropy
}
