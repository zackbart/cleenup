package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

func main() {
	text := `STRIPE_SECRET_KEY=` + "sk_" + `live_TESTKEY00000000000000000
OPENAI_API_KEY=sk-proj-abc123def456ghi789jkl012mno345pqr678
GITHUB_TOKEN=ghp_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8`

	prompt := fmt.Sprintf(`You are a secret/credential detector. Analyze the following text from a CLI session log.

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
---`, text)

	body, _ := json.Marshal(map[string]any{
		"model":       "",
		"messages":    []map[string]string{
			{"role": "system", "content": "/no_think"},
			{"role": "user", "content": prompt},
		},
		"max_tokens":  2048,
		"temperature": 0,
	})

	resp, err := http.Post("http://localhost:1234/v1/chat/completions", "application/json", bytes.NewReader(body))
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	respBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	var result map[string]any
	json.Unmarshal(respBody, &result)
	choices := result["choices"].([]any)
	msg := choices[0].(map[string]any)["message"].(map[string]any)
	content := msg["content"].(string)

	fmt.Printf("Has <think>: %v\n", len(content) > 7 && content[:7] == "<think>")
	fmt.Printf("Response length: %d chars\n\n")
	fmt.Printf("Raw:\n%s\n", content)
}
