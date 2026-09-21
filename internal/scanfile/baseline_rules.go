package scanfile

import "regexp"

// baselineRules covers well-known, publicly documented credential formats
// that nullifyRules doesn't already handle (nullifyRules is Nullify's own
// additions layered on top of gitleaks' several-hundred-rule default set;
// this package doesn't vendor that default set -- see scanfile.go's package
// doc). It is not a claim of parity with gitleaks' breadth: it is a
// deliberately small, high-confidence set for the formats most likely to
// turn up in a file someone is actively editing.
func baselineRules() []Rule {
	return []Rule{
		{
			ID:       "aws-access-key-id",
			Regex:    regexp.MustCompile(`\b((?:AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16})\b`),
			Keywords: []string{"akia", "asia", "abia", "acca"},
		},
		{
			ID:         "aws-secret-access-key",
			Regex:      regexp.MustCompile(`(?i)aws[a-z0-9_.-]{0,20}?(?:secret|access)[a-z0-9_.-]{0,20}?key[a-z0-9_.-]{0,20}?\s*[:=]\s*['"]?([A-Za-z0-9/+=]{40})['"]?`),
			Keywords:   []string{"aws"},
			MinEntropy: 4.0,
		},
		{
			ID:       "github-pat",
			Regex:    regexp.MustCompile(`\bgh[oprsu]_[A-Za-z0-9]{36,251}\b`),
			Keywords: []string{"ghp_", "gho_", "ghr_", "ghs_", "ghu_"},
		},
		{
			ID:       "gitlab-pat",
			Regex:    regexp.MustCompile(`\bglpat-[A-Za-z0-9_-]{20}\b`),
			Keywords: []string{"glpat-"},
		},
		{
			ID:       "slack-token",
			Regex:    regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,72}\b`),
			Keywords: []string{"xoxb-", "xoxa-", "xoxp-", "xoxr-", "xoxs-"},
		},
		{
			ID:       "slack-webhook-url",
			Regex:    regexp.MustCompile(`https://hooks\.slack\.com/services/T[A-Za-z0-9]{6,}/B[A-Za-z0-9]{6,}/[A-Za-z0-9]{16,}`),
			Keywords: []string{"hooks.slack.com"},
		},
		{
			ID:       "stripe-secret-key",
			Regex:    regexp.MustCompile(`\bsk_live_[A-Za-z0-9]{24,}\b`),
			Keywords: []string{"sk_live_"},
		},
		{
			ID:       "stripe-restricted-key",
			Regex:    regexp.MustCompile(`\brk_live_[A-Za-z0-9]{24,}\b`),
			Keywords: []string{"rk_live_"},
		},
		{
			ID:       "google-api-key",
			Regex:    regexp.MustCompile(`\bAIza[A-Za-z0-9_-]{35}\b`),
			Keywords: []string{"AIza"},
		},
		{
			ID:       "pem-private-key",
			Regex:    regexp.MustCompile(`-----BEGIN\s?((?:RSA|EC|DSA|OPENSSH|PGP)\s)?PRIVATE KEY(\sBLOCK)?-----`),
			Keywords: []string{"private key"},
		},
		{
			ID:       "npm-access-token",
			Regex:    regexp.MustCompile(`\bnpm_[A-Za-z0-9]{36}\b`),
			Keywords: []string{"npm_"},
		},
		{
			ID:       "twilio-api-key",
			Regex:    regexp.MustCompile(`\bSK[0-9a-fA-F]{32}\b`),
			Keywords: []string{"twilio"},
		},
		{
			ID:       "sendgrid-api-key",
			Regex:    regexp.MustCompile(`\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b`),
			Keywords: []string{"sg."},
		},
		{
			ID:       "mailgun-api-key",
			Regex:    regexp.MustCompile(`\bkey-[a-f0-9]{32}\b`),
			Keywords: []string{"mailgun", "key-"},
		},
		{
			ID:       "discord-bot-token",
			Regex:    regexp.MustCompile(`\b[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}\b`),
			Keywords: []string{"discord"},
		},
		{
			ID:       "azure-storage-connection-string",
			Regex:    regexp.MustCompile(`(?i)DefaultEndpointsProtocol=https?;AccountName=[A-Za-z0-9]+;AccountKey=[A-Za-z0-9+/=]{20,};`),
			Keywords: []string{"accountkey="},
		},
		{
			ID:       "heroku-api-key",
			Regex:    regexp.MustCompile(`(?i)heroku[a-z0-9_.-]{0,20}?(?:api)?[a-z0-9_.-]{0,20}?key\s*[:=]\s*['"]?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['"]?`),
			Keywords: []string{"heroku"},
		},
		{
			ID:         "generic-api-key",
			Regex:      regexp.MustCompile(`(?i)(?:secret|token|api[_-]?key|apikey|password|passwd|credential)\s*[:=]\s*['"]([A-Za-z0-9+/=_.-]{16,64})['"]`),
			Keywords:   []string{"secret", "token", "key", "password", "passwd", "credential"},
			MinEntropy: 4.0,
		},
	}
}
