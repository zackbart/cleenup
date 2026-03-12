package model

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"cleenup/internal/report"
)

type Client struct {
	baseURL   string
	modelName string
	client    *http.Client
	sem       chan struct{} // concurrency limiter
}

func NewClient(port int, modelName string) *Client {
	return &Client{
		baseURL:   fmt.Sprintf("http://localhost:%d", port),
		modelName: modelName,
		client:    &http.Client{Timeout: 120 * time.Second},
		sem:       make(chan struct{}, 4), // max 4 concurrent requests
	}
}

func (c *Client) ModelName() string {
	return c.modelName
}

type modelsResponse struct {
	Data []struct {
		ID string `json:"id"`
	} `json:"data"`
}

func (c *Client) CheckConnection() error {
	resp, err := c.client.Get(c.baseURL + "/v1/models")
	if err != nil {
		return fmt.Errorf("cannot connect: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("cannot read response: %w", err)
	}

	var models modelsResponse
	if err := json.Unmarshal(body, &models); err != nil {
		return fmt.Errorf("cannot parse models response: %w", err)
	}

	if len(models.Data) == 0 {
		return fmt.Errorf("no models loaded in LM Studio — load a model first")
	}

	// Auto-detect model if not specified
	if c.modelName == "" {
		// Pick the first non-embedding model
		for _, m := range models.Data {
			if !strings.Contains(m.ID, "embed") {
				c.modelName = m.ID
				break
			}
		}
		if c.modelName == "" {
			c.modelName = models.Data[0].ID
		}
	}

	return nil
}

type chatRequest struct {
	Model       string        `json:"model"`
	Messages    []chatMessage `json:"messages"`
	MaxTokens   int           `json:"max_tokens"`
	Temperature float64       `json:"temperature"`
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
}

type modelFinding struct {
	Value string `json:"value"`
	Type  string `json:"type"`
}

const classificationPrompt = `You are a secret/credential detector. Analyze the following text from a CLI session log.

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
---`

func (c *Client) Classify(text string) ([]modelFinding, error) {
	// Acquire semaphore
	c.sem <- struct{}{}
	defer func() { <-c.sem }()

	// Truncate very long texts to avoid overwhelming the model
	if len(text) > 4000 {
		text = text[:4000]
	}

	prompt := fmt.Sprintf(classificationPrompt, text)

	reqBody := chatRequest{
		Model: c.modelName,
		Messages: []chatMessage{
			{Role: "system", Content: "/no_think"},
			{Role: "user", Content: prompt},
		},
		MaxTokens:   1024,
		Temperature: 0,
	}

	data, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	resp, err := c.client.Post(c.baseURL+"/v1/chat/completions", "application/json", bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("model request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var chatResp chatResponse
	if err := json.Unmarshal(body, &chatResp); err != nil {
		return nil, fmt.Errorf("cannot parse model response: %w", err)
	}

	if len(chatResp.Choices) == 0 {
		return nil, nil
	}

	content := strings.TrimSpace(chatResp.Choices[0].Message.Content)

	// Extract JSON array from response — handles thinking models that output
	// reasoning before the actual JSON answer
	content = extractJSONArray(content)

	var findings []modelFinding
	if err := json.Unmarshal([]byte(content), &findings); err != nil {
		// Model returned non-JSON — skip
		return nil, nil
	}

	return findings, nil
}

// ClassifyChunks runs model classification on pre-filtered chunks concurrently.
// Returns additional findings detected by the model.
func (c *Client) ClassifyChunks(chunks []ChunkForModel, progress func(done, total int)) []report.Finding {
	var (
		mu       sync.Mutex
		findings []report.Finding
		wg       sync.WaitGroup
		done     int
	)

	for _, chunk := range chunks {
		wg.Add(1)
		go func(ch ChunkForModel) {
			defer wg.Done()

			mFindings, err := c.Classify(ch.Text)
			if err != nil {
				// Skip on error, don't fail the whole scan
				mu.Lock()
				done++
				if progress != nil {
					progress(done, len(chunks))
				}
				mu.Unlock()
				return
			}

			mu.Lock()
			for _, mf := range mFindings {
				if mf.Value == "" {
					continue
				}
				// Build context
				idx := strings.Index(ch.Text, mf.Value)
				ctx := mf.Value
				if idx >= 0 {
					start := max(0, idx-40)
					end := min(len(ch.Text), idx+len(mf.Value)+40)
					ctx = ch.Text[start:end]
				}
				findings = append(findings, report.Finding{
					Source:      ch.Source,
					SessionFile: ch.SessionFile,
					PatternName: fmt.Sprintf("LLM: %s", mf.Type),
					MatchedText: mf.Value,
					Context:     strings.ReplaceAll(ctx, "\n", " "),
					Timestamp:   ch.Timestamp,
					Layer:       report.LayerModel,
				})
			}
			done++
			if progress != nil {
				progress(done, len(chunks))
			}
			mu.Unlock()
		}(chunk)
	}

	wg.Wait()
	return findings
}

// jsonArrayPattern matches a JSON array in model output, handling thinking models
// that output reasoning before the actual answer.
var jsonArrayPattern = regexp.MustCompile(`\[[\s\S]*\]`)

// extractJSONArray extracts the JSON array answer from model output.
// Handles thinking models (Qwen 3.5, etc.) that wrap reasoning in <think>...</think> tags.
func extractJSONArray(text string) string {
	// Strip <think>...</think> blocks first
	if idx := strings.Index(text, "</think>"); idx >= 0 {
		text = text[idx+len("</think>"):]
	}

	// Strip markdown code fences
	text = strings.ReplaceAll(text, "```json", "")
	text = strings.ReplaceAll(text, "```", "")
	text = strings.TrimSpace(text)

	// If it already parses as JSON, return it
	var test []json.RawMessage
	if json.Unmarshal([]byte(text), &test) == nil {
		return text
	}

	// Otherwise find the last valid JSON array in the remaining text
	matches := jsonArrayPattern.FindAllString(text, -1)
	for i := len(matches) - 1; i >= 0; i-- {
		candidate := strings.TrimSpace(matches[i])
		if json.Unmarshal([]byte(candidate), &test) == nil {
			return candidate
		}
	}

	return strings.TrimSpace(text)
}

// ChunkForModel represents a pre-filtered text chunk to send to the model.
type ChunkForModel struct {
	Text        string
	Source      string
	SessionFile string
	Timestamp   string
}
