package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
)

func main() {
	text := `Here's the .env file for the production server:

STRIPE_SECRET_KEY=` + "sk_" + `live_TESTKEY00000000000000000
OPENAI_API_KEY=sk-proj-abc123def456ghi789jkl012mno345pqr678
DATABASE_URL=postgresql://admin:R3allyS3cretP@ss!@db.prod.example.com:5432/myapp
GITHUB_TOKEN=ghp_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8`

	// Test 3 different prompts
	prompts := map[string]string{
		"current": fmt.Sprintf(`You are a secret/credential detector. Analyze the following text from a CLI session log.

Identify any REAL secret values — API keys, passwords, tokens, connection strings, private keys, or other credentials.

Rules:
- Only flag actual secret VALUES, not variable names or references like process.env.FOO
- Ignore placeholder values like "your-api-key", "changeme", "xxx", "<token>"
- Ignore UUIDs, git commit hashes, and non-secret identifiers
- Be precise: return the exact string that is the secret

Return ONLY a JSON array: [{"value": "exact secret string", "type": "description"}]
Return [] if no secrets found. No explanation, no markdown, just the JSON array.

Text:
---
%s
---`, text),

		"simple": fmt.Sprintf(`Find all secrets in this text. Return a JSON array of {"value": "the secret", "type": "what kind"}.

%s`, text),

		"few-shot": fmt.Sprintf(`Find secrets (API keys, passwords, tokens) in the text below.

Example input: API_KEY=` + "sk_" + `live_abc123
Example output: [{"value": "` + "sk_" + `live_abc123", "type": "Stripe key"}]

Example input: NODE_ENV=production
Example output: []

Now find secrets in:
%s`, text),
	}

	for name, prompt := range prompts {
		fmt.Printf("\n=== Prompt: %s ===\n", name)

		body, _ := json.Marshal(map[string]any{
			"model":       "",
			"messages":    []map[string]string{{"role": "user", "content": prompt}},
			"max_tokens":  1024,
			"temperature": 0,
		})

		resp, err := http.Post("http://localhost:1234/v1/chat/completions", "application/json", bytes.NewReader(body))
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			continue
		}

		respBody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		var result map[string]any
		json.Unmarshal(respBody, &result)

		choices, _ := result["choices"].([]any)
		if len(choices) == 0 {
			fmt.Println("No choices returned")
			continue
		}
		choice := choices[0].(map[string]any)
		msg := choice["message"].(map[string]any)
		content := msg["content"].(string)

		fmt.Printf("Raw response:\n%s\n", content)
	}

	os.Exit(0)
}
