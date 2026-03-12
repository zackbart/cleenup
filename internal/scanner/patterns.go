package scanner

import "regexp"

// SecretPattern pairs a compiled regex with a human-readable name.
type SecretPattern struct {
	Pattern *regexp.Regexp
	Name    string
}

// secretPatterns holds every regex-based secret pattern used by the scanner.
var secretPatterns []SecretPattern

func init() {
	raw := []struct {
		pattern string
		name    string
	}{
		// API keys with known prefixes (specific patterns only — generic sk- removed to reduce false positives)
		{`sk-ant-[a-zA-Z0-9\-]{20,}`, "Anthropic API key"},
		{`sk-proj-[a-zA-Z0-9\-]{20,}`, "OpenAI project key"},
		{`ghp_[a-zA-Z0-9]{36,}`, "GitHub PAT"},
		{`gho_[a-zA-Z0-9]{36,}`, "GitHub OAuth token"},
		{`ghu_[a-zA-Z0-9]{36,}`, "GitHub user token"},
		{`ghs_[a-zA-Z0-9]{36,}`, "GitHub server token"},
		{`github_pat_[a-zA-Z0-9_]{36,}`, "GitHub fine-grained PAT"},
		{`glpat-[a-zA-Z0-9\-]{20,}`, "GitLab PAT"},
		{`AKIA[0-9A-Z]{16}`, "AWS access key ID"},
		{`xoxb-[0-9]{10,}-[0-9a-zA-Z]{20,}`, "Slack bot token"},
		{`xoxp-[0-9]{10,}-[0-9a-zA-Z]{20,}`, "Slack user token"},
		{`xoxs-[0-9]{10,}-[0-9a-zA-Z]{20,}`, "Slack session token"},
		{`xapp-[0-9]{1,}-[a-zA-Z0-9]{10,}-[0-9]{10,}-[a-zA-Z0-9]{30,}`, "Slack app token"},
		{`hooks\.slack\.com/services/T[a-zA-Z0-9_]{8,}/B[a-zA-Z0-9_]{8,}/[a-zA-Z0-9_]{20,}`, "Slack webhook URL"},
		{`SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}`, "SendGrid API key"},
		{`sq0[a-z]{3}-[a-zA-Z0-9\-_]{22,}`, "Square API key"},
		{`sk_live_[a-zA-Z0-9]{24,}`, "Stripe live secret key"},
		{`rk_live_[a-zA-Z0-9]{24,}`, "Stripe restricted key"},
		{`pk_live_[a-zA-Z0-9]{24,}`, "Stripe live publishable key"},
		{`whsec_[a-zA-Z0-9]{20,}`, "Stripe webhook secret"},
		{`npm_[a-zA-Z0-9]{20,}`, "npm token"},
		{`pypi-[a-zA-Z0-9\-]{50,}`, "PyPI API token"},
		{`napi_[a-zA-Z0-9]{20,}`, "Notion API key"},
		{`hf_[a-zA-Z0-9]{20,}`, "Hugging Face token"},
		{`AIza[0-9A-Za-z_\-]{35}`, "Google API key"},
		{`ya29\.[0-9A-Za-z_\-]{50,}`, "Google OAuth token"},
		{`eyJ[a-zA-Z0-9_\-]{20,}\.eyJ[a-zA-Z0-9_\-]{20,}\.[a-zA-Z0-9_\-]{20,}`, "JWT token"},
		{`dop_v1_[a-f0-9]{64}`, "DigitalOcean PAT"},
		{`tskey-[a-zA-Z0-9]{6,}-[a-zA-Z0-9]{20,}`, "Tailscale API key"},
		{`age1[a-z0-9]{58}`, "age encryption key"},
		{`-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----`, "Private key"},
		{`-----BEGIN CERTIFICATE-----`, "Certificate"},
		{`vercel_[a-zA-Z0-9]{20,}`, "Vercel token"},
		{`sbp_[a-f0-9]{40}`, "Supabase token"},
		{`nfp_[a-zA-Z0-9]{40}`, "Netlify PAT"},
		{`(?:^|[^a-zA-Z0-9])AC[a-f0-9]{32}(?:[^a-f0-9]|$)`, "Twilio account SID"},
		{`PMAK-[a-f0-9]{24}-[a-f0-9]{34}`, "Postman API key"},
		// Connection strings with embedded credentials
		{`(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?|mssql|cockroachdb|nats)://[^\s"'` + "`" + `]{5,}@[^\s"'` + "`" + `]+`, "Connection string with credentials"},
		// Stripe/WorkOS test keys
		{`sk_test_[a-zA-Z0-9]{20,}`, "Stripe/test secret key"},
		// Sentry auth token
		{`sntrys_[a-zA-Z0-9]{20,}`, "Sentry auth token"},
	}

	secretPatterns = make([]SecretPattern, len(raw))
	for i, r := range raw {
		secretPatterns[i] = SecretPattern{
			Pattern: regexp.MustCompile(r.pattern),
			Name:    r.name,
		}
	}
}

// envAssignmentPattern matches shell-style variable assignments such as
// export SECRET_KEY="value" or TOKEN=abc123.
var envAssignmentPattern = regexp.MustCompile(
	`(?:^|[\s;|&])(?:export\s+)?([A-Z][A-Z0-9_]{2,})\s*=\s*["']?([^\s"';\n]{8,})["']?`,
)

// sensitiveVarNames contains exact environment variable names that are
// considered sensitive.
var sensitiveVarNames = map[string]bool{
	"API_KEY":                        true,
	"APIKEY":                         true,
	"API_SECRET":                     true,
	"SECRET_KEY":                     true,
	"SECRET":                         true,
	"ACCESS_KEY":                     true,
	"ACCESS_TOKEN":                   true,
	"AUTH_TOKEN":                     true,
	"TOKEN":                          true,
	"PASSWORD":                       true,
	"PASSWD":                         true,
	"PASS":                           true,
	"DATABASE_URL":                   true,
	"DB_URL":                         true,
	"DB_PASSWORD":                    true,
	"DB_PASS":                        true,
	"MONGODB_URI":                    true,
	"MONGO_URI":                      true,
	"REDIS_URL":                      true,
	"PRIVATE_KEY":                    true,
	"ENCRYPTION_KEY":                 true,
	"AWS_SECRET_ACCESS_KEY":          true,
	"AWS_ACCESS_KEY_ID":              true,
	"AWS_SESSION_TOKEN":              true,
	"OPENAI_API_KEY":                 true,
	"ANTHROPIC_API_KEY":              true,
	"CLAUDE_API_KEY":                 true,
	"STRIPE_SECRET_KEY":              true,
	"STRIPE_KEY":                     true,
	"GITHUB_TOKEN":                   true,
	"GH_TOKEN":                       true,
	"GITLAB_TOKEN":                   true,
	"SLACK_TOKEN":                    true,
	"SLACK_WEBHOOK":                  true,
	"SENDGRID_API_KEY":               true,
	"TWILIO_AUTH_TOKEN":              true,
	"SUPABASE_KEY":                   true,
	"SUPABASE_SERVICE_ROLE_KEY":      true,
	"NEXT_PUBLIC_SUPABASE_ANON_KEY":  true,
	"FIREBASE_API_KEY":               true,
	"FIREBASE_TOKEN":                 true,
	"VERCEL_TOKEN":                   true,
	"NETLIFY_AUTH_TOKEN":             true,
	"NPM_TOKEN":                      true,
	"PYPI_TOKEN":                     true,
	"SENTRY_DSN":                     true,
	"SENTRY_AUTH_TOKEN":              true,
	"POSTGRES_PASSWORD":              true,
	"MYSQL_PASSWORD":                 true,
	"JWT_SECRET":                     true,
	"SESSION_SECRET":                 true,
	"COOKIE_SECRET":                  true,
	"WEBHOOK_SECRET":                 true,
	"SIGNING_SECRET":                 true,
	"CLIENT_SECRET":                  true,
	"CLIENT_ID":                      true,
	"CONNECTION_STRING":              true,
	"RESEND_API_KEY":                 true,
	"WORKOS_API_KEY":                 true,
	"WORKOS_CLIENT_ID":               true,
	"MIXPANEL_PROJECT_TOKEN":         true,
	"NANOMDM_API_KEY":                true,
	"NANOMDM_STORAGE_DSN":            true,
	"VITE_SENTRY_DSN":                true,
	"VITE_MIXPANEL_TOKEN":            true,
	"BUCKET_SECRET_ACCESS_KEY":       true,
	"BUCKET_ACCESS_KEY_ID":           true,
	"STEP_CA_PASSWORD":               true,
}

// sensitiveSubstrings are checked against variable names when the exact name
// is not found in sensitiveVarNames.
var sensitiveSubstrings = []string{
	"SECRET",
	"TOKEN",
	"PASSWORD",
	"PASSWD",
	"KEY",
	"CREDENTIAL",
	"AUTH",
	"PRIVATE",
	"SIGNING",
	"ENCRYPT",
	"DSN",
	"WEBHOOK",
}
