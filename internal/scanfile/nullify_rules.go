package scanfile

import "regexp"

func nullifyRules() []Rule {
	return []Rule{
		{
			ID:       "artifactory-api-token",
			Regex:    regexp.MustCompile(`(?:[^A-Za-z0-9/+]|^)(AKC[a-zA-Z0-9]{10,})(?:[^A-Za-z0-9/+]|$)`),
			Keywords: []string{"artifactory", "api", "token", "akc"},
		},
		{
			ID:       "artifactory-password",
			Regex:    regexp.MustCompile(`(?:[^A-Za-z0-9/+]|^)(AP[0-9ABCDEF][a-zA-Z0-9]{8,})(?:[^A-Za-z0-9/+]|$)`),
			Keywords: []string{"artifactory", "password", "ap"},
		},
		{
			ID:       "basic-auth",
			Regex:    regexp.MustCompile(`://[^:/\?\#\[\]@!\$\&'\(\)\*\+,;=\s]+:([^:/\?\#\[\]@!\$\&'\(\)\*\+,;=\s]+)@`),
			Keywords: []string{"://", "http", "https", "ftp"},
		},
		{
			ID:       "cloudant-credentials",
			Regex:    regexp.MustCompile(`(?im)((?:https?\:\/\/)[\w\-]+\:([0-9a-f]{64})\@[\w\-]+\.cloudant\.com)|((?:https?\:\/\/)[\w\-]+\:([a-z]{24})\@[\w\-]+\.cloudant\.com)|(?:^|\W)(?:\[|)(?:"|\'|)(?:cloudant|cl|clou)(?:_|-|)(?:api|)(?:key|pwd|pw|password|pass|token)(?:"|\'|)(?:\]|)(?: *)(?:=|:|:=|=>| +|::)(?: *)(?:"|\'|)([0-9a-f]{64})(?:"|\'|)|(?:^|\W)(?:\[|)(?:"|\'|)(?:cloudant|cl|clou)(?:_|-|)(?:api|)(?:key|pwd|pw|password|pass|token)(?:"|\'|)(?:\]|)(?: *)(?:=|:|:=|=>| +|::)(?: *)(?:"|\'|)([a-z]{24})(?:"|\'|)`),
			Keywords: []string{"cloudant", "ibm", "cloud"},
		},
		{
			ID:       "ibm-cloud-iam-key",
			Regex:    regexp.MustCompile(`(?im)(?:^|\W)(?:\[|)(?:"|\'|)(?:ibm(?:_|-|)cloud(?:_|-|)iam|cloud(?:_|-|)iam|ibm(?:_|-|)cloud|ibm(?:_|-|)iam|ibm|iam|cloud|)(?:_|-|)(?:api|)(?:_|-|)(?:key|pwd|password|pass|token)(?:"|\'|)(?:\]|)(?: *)(?:=|:|:=|=>| +|::)(?: *)(?:"|\'|)([a-zA-Z0-9_\-]{44}[^a-zA-Z0-9_\-])(?:"|\'|)`),
			Keywords: []string{"ibm", "cloud", "iam", "key"},
		},
		{
			ID:       "ibm-cos-hmac-credentials",
			Regex:    regexp.MustCompile(`(?i)(?:^|\W)(?:\[|)(?:"|\'|)(?:(?:ibm)?[-_]?cos[-_]?(?:hmac)?|)(?:_|-|)(?:secret[-_]?(?:access)?[-_]?key)(?:"|\'|)(?:\]|)(?: *)(?:=|:|:=|=>| +|::)(?: *)(?:"|\'|)([a-f0-9]{48}[^a-f0-9])(?:"|\'|)`),
			Keywords: []string{"ibm", "cos", "hmac", "secret"},
		},
		{
			ID:       "softlayer-api-key",
			Regex:    regexp.MustCompile(`(?im)(?:^|\W)(?:\[|)(?:"|\'|)(?:softlayer|sl)(?:_|-|)(?:api|)(?:_|-|)(?:key|pwd|password|pass|token)(?:"|\'|)(?:\]|)(?: *)(?:=|:|:=|=>| +|::)(?: *)(?:"|\'|)([a-z0-9]{64})(?:"|\'|)|(?:http|https)://api.softlayer.com/soap/(?:v3|v3.1)/([a-z0-9]{64})`),
			Keywords: []string{"softlayer", "sl", "api", "key"},
		},
		{
			ID:       "anthropic-api-key",
			Regex:    regexp.MustCompile(`sk-ant-api03-[A-Za-z0-9_\-]{93}AA`),
			Keywords: []string{"sk-ant-api03"},
		},
		{
			ID:       "openai-project-key",
			Regex:    regexp.MustCompile(`sk-proj-[A-Za-z0-9_\-]{40,}`),
			Keywords: []string{"sk-proj-"},
		},
		{
			ID:       "gcp-oauth-client-secret",
			Regex:    regexp.MustCompile(`GOCSPX-[A-Za-z0-9_\-]{28}`),
			Keywords: []string{"GOCSPX-"},
		},
		{
			ID:         "cloudflare-api-token",
			Regex:      regexp.MustCompile(`(?i)(?:cloudflare|cf)[\s_-]*(?:api)?[\s_-]*(?:token|key)['"]?\s*(?:=|:|:=)\s*['"]?([A-Za-z0-9_\-]{40})['"]?`),
			Keywords:   []string{"cloudflare", "cf_api"},
			MinEntropy: 3.5,
		},
		{
			ID:       "vercel-api-token",
			Regex:    regexp.MustCompile(`vc_[A-Za-z0-9]{24}`),
			Keywords: []string{"vc_"},
		},
		{
			ID:       "flyio-api-token",
			Regex:    regexp.MustCompile(`FlyV1\s+fm2_[A-Za-z0-9_\-/+=]{100,}`),
			Keywords: []string{"FlyV1", "fm2_"},
		},
		{
			ID:       "tailscale-api-key",
			Regex:    regexp.MustCompile(`tskey-(?:api|auth|client)-[A-Za-z0-9]{10,}-[A-Za-z0-9]{20,}`),
			Keywords: []string{"tskey-"},
		},
		{
			ID:       "infisical-api-token",
			Regex:    regexp.MustCompile(`st\.(?:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9a-f]{24})\.[0-9a-f]{32}\.[0-9a-f]{32}`),
			Keywords: []string{"st."},
		},
		{
			ID:       "onepassword-service-account-token",
			Regex:    regexp.MustCompile(`ops_eyJ[A-Za-z0-9+/=_\-]{200,}`),
			Keywords: []string{"ops_eyJ"},
		},
		{
			ID:         "railway-api-token",
			Regex:      regexp.MustCompile(`(?i)railway[\s_-]*(?:api)?[\s_-]*(?:token|key)['"]?\s*(?:=|:|:=)\s*['"]?([a-f0-9\-]{36})['"]?`),
			Keywords:   []string{"railway"},
			MinEntropy: 3.0,
		},
		{
			ID:       "postmark-server-token",
			Regex:    regexp.MustCompile(`(?i)postmark[\s_-]*(?:server)?[\s_-]*(?:token|key|api)['"]?\s*(?:=|:|:=)\s*['"]?([a-f0-9\-]{36})['"]?`),
			Keywords: []string{"postmark"},
		},
		{
			ID:       "neon-database-url",
			Regex:    regexp.MustCompile(`postgres(?:ql)?://[^:]+:[^@]+@[^/]*\.neon\.tech`),
			Keywords: []string{"neon.tech"},
		},
		{
			ID:       "supabase-pat",
			Regex:    regexp.MustCompile(`sbp_[a-f0-9]{40}`),
			Keywords: []string{"sbp_"},
		},
		{
			ID:       "groq-api-key",
			Regex:    regexp.MustCompile(`\b(gsk_[a-zA-Z0-9]{52})\b`),
			Keywords: []string{"gsk_"},
		},
		{
			ID:        "deepseek-api-key",
			Regex:     regexp.MustCompile(`(?i:deepseek)(?:.|[\n\r]){0,40}?\b(sk-[a-z0-9]{32})\b`),
			Keywords:  []string{"deepseek"},
			Multiline: true,
		},
		{
			ID:       "google-gemini-api-key",
			Regex:    regexp.MustCompile(`\b(AIzaSy[A-Za-z0-9_-]{33})`),
			Keywords: []string{"AIzaSy"},
		},
		{
			ID:       "xai-api-key",
			Regex:    regexp.MustCompile(`\b(xai-[0-9a-zA-Z_]{80})\b`),
			Keywords: []string{"xai-"},
		},
		{
			ID:       "replicate-api-key",
			Regex:    regexp.MustCompile(`\b(r8_[0-9A-Za-z\-_]{37})\b`),
			Keywords: []string{"r8_"},
		},
		{
			ID:       "fireworks-api-key",
			Regex:    regexp.MustCompile(`fw_[A-Za-z0-9]{20,44}`),
			Keywords: []string{"fw_"},
		},
		{
			ID:       "openrouter-api-key",
			Regex:    regexp.MustCompile(`\b(sk-or-v1-[0-9a-f]{64})\b`),
			Keywords: []string{"sk-or-v1-"},
		},
		{
			ID:       "figma-pat",
			Regex:    regexp.MustCompile(`\b(figd_[A-Za-z0-9_-]{40,})\b`),
			Keywords: []string{"figd_"},
		},
		{
			ID:       "posthog-personal-api-key",
			Regex:    regexp.MustCompile(`\b(phx_[A-Za-z0-9]{40,})\b`),
			Keywords: []string{"phx_"},
		},
		{
			ID:       "cloudinary-url",
			Regex:    regexp.MustCompile(`cloudinary://[0-9]{15}:[A-Za-z0-9_-]{20,}@[a-zA-Z0-9_-]+`),
			Keywords: []string{"cloudinary://"},
		},
		{
			ID:       "stripe-webhook-secret",
			Regex:    regexp.MustCompile(`\b(whsec_[A-Za-z0-9]{32,})\b`),
			Keywords: []string{"whsec_"},
		},
		{
			ID:       "dockerhub-pat",
			Regex:    regexp.MustCompile(`\b(dckr_pat_[A-Za-z0-9_-]{20,})\b`),
			Keywords: []string{"dckr_pat_"},
		},
		{
			ID:       "github-installation-token-jwt",
			Regex:    regexp.MustCompile(`gh[us]_[0-9]+_[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`),
			Keywords: []string{"ghs_", "ghu_"},
		},
		{
			ID:       "vixverify-greenid-api-code",
			Regex:    regexp.MustCompile(`(?i)green[_-]?id[_-]?api[_-]?code['"]?\s*[:=]\s*['"]?([A-Za-z0-9]{3}-[A-Za-z0-9]{3}-[A-Za-z0-9]{3}-[A-Za-z0-9]{3})['"]?`),
			Keywords: []string{"green_id", "greenid", "green-id", "vixverify"},
		},
	}
}
