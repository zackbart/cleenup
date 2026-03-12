package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// generateFixtures creates test .txt files with synthetic secrets.
// These files are gitignored because they contain patterns that trigger
// GitHub Push Protection. Run this before model_accuracy.go or debug tools.

func main() {
	_, thisFile, _, _ := runtime.Caller(0)
	dir := filepath.Dir(thisFile)

	fixtures := map[string]string{
		"01_obvious_secrets.txt": "Here's the .env file for the production server:\n\n" +
			"STRIPE_SECRET_KEY=" + "sk_" + "live_TESTKEY00000000000000000\n" +
			"OPENAI_API_KEY=sk-proj-abc123def456ghi789jkl012mno345pqr678\n" +
			"DATABASE_URL=postgresql://admin:R3allyS3cretP@ss!@db.prod.example.com:5432/myapp\n" +
			"GITHUB_TOKEN=ghp_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8\n" +
			"AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYzzzKEY\n",

		"02_inline_secrets.txt": "Here's a curl command I ran:\n\n" +
			"$ curl -H \"Authorization: Bearer sk-ant-api03-xK9mN2pQ5rT8vW1yB4dF7gJ0lO3sU6hA9cE2iM5nP8qR1tV4wX7zA0bD3fG6jK-abcdefgh\" https://api.anthropic.com/v1/messages\n\n" +
			"And here's the Stripe webhook secret: whsec_MhdbMVxK7P2NqR9sT4uW1xY3zA5bC7dE\n\n" +
			"The database password is x8Km$nP2qR!vT4w\n",

		"03_subtle_secrets.txt": "Config file contents:\n\n" +
			"api_key: mK9xP2nQ5rT8vW1yB4dF7gJ0lO3sU6hA\n" +
			"password: Tr0ub4dor&3xCh@ng3M3N0w!\n" +
			"clever_token: clv_prod_9a8b7c6d5e4f3g2h1i0j\n" +
			"hmac_secret: a4f8e2d1c7b3a9f5e0d6c2b8a4f0e6d2c8b4a0f6e2d8c4b0a6f2e8d4c0b6a2f8\n",

		"04_false_positives.txt": "Here are things that should NOT be flagged:\n\n" +
			"NODE_ENV=production\n" +
			"PORT=3000\n" +
			"API_URL=https://api.example.com\n" +
			"DEBUG=true\n" +
			"The commit hash is abc123def456789\n" +
			"UUID: 550e8400-e29b-41d4-a716-446655440000\n",

		"05_mixed_context.txt": "From the Resend dashboard:\n" +
			"re_7xKm9Np2Qr4St6Uv8Wx0Ya2Bc4De6Fg\n\n" +
			"Redis connection: redis://default:abc123def456@redis.example.com:6379\n\n" +
			"Old password was myR3disP@ssw0rd\n",
	}

	for name, content := range fixtures {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			fmt.Printf("Error writing %s: %v\n", name, err)
			continue
		}
		fmt.Printf("Generated %s\n", name)
	}
}
