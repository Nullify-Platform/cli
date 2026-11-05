package scanfile

import (
	"math"
	"regexp"
	"strings"
	"sync"
)

// Rule defines a secret pattern and its detection limits.
type Rule struct {
	ID         string
	Regex      *regexp.Regexp
	Keywords   []string
	MinEntropy float64
	Multiline  bool
}

var acronyms = map[string]string{
	"aws": "AWS", "api": "API", "jwt": "JWT", "iam": "IAM", "cos": "COS",
	"hmac": "HMAC", "gcp": "GCP", "ibm": "IBM", "pat": "PAT", "id": "ID",
	"url": "URL", "npm": "NPM", "sql": "SQL", "pem": "PEM", "sdk": "SDK",
	"greenid": "GreenID", "oauth": "OAuth", "openai": "OpenAI", "xai": "xAI",
	"vixverify": "VixVerify",
}

// Title returns the display name for a rule.
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

func rules() []Rule {
	return rulesOnce()
}

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
