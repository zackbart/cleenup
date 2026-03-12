package scanner

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

// WalkCodexFiles walks ~/.codex/sessions/ recursively and also includes
// ~/.codex/history.jsonl. Returns all .jsonl file paths.
func WalkCodexFiles() ([]string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	var files []string

	// Include history file
	historyFile := filepath.Join(home, ".codex", "history.jsonl")
	if _, err := os.Stat(historyFile); err == nil {
		files = append(files, historyFile)
	}

	// Walk session logs
	root := filepath.Join(home, ".codex", "sessions")
	if _, err := os.Stat(root); os.IsNotExist(err) {
		return files, nil
	}

	err = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !info.IsDir() && strings.HasSuffix(path, ".jsonl") {
			files = append(files, path)
		}
		return nil
	})
	return files, err
}

// ParseCodexHistoryFile reads the Codex history.jsonl file. Each line has
// a "text" field containing the user's prompt.
func ParseCodexHistoryFile(path string) (chunks []TextChunk, messageCount int, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()

	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 0, 10*1024*1024), 10*1024*1024)

	for s.Scan() {
		var entry map[string]any
		if err := json.Unmarshal(s.Bytes(), &entry); err != nil {
			continue
		}

		messageCount++

		if text, ok := entry["text"].(string); ok && text != "" {
			chunks = append(chunks, TextChunk{
				Text:        text,
				Source:      "codex",
				SessionFile: path,
				Timestamp:   "",
			})
		}
	}

	if err := s.Err(); err != nil {
		return chunks, messageCount, err
	}
	return chunks, messageCount, nil
}

// ParseCodexFile reads a Codex JSONL session log and extracts all text chunks
// where secrets could appear. messageCount tracks entries that produced chunks.
func ParseCodexFile(path string) (chunks []TextChunk, messageCount int, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()

	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 0, 10*1024*1024), 10*1024*1024)

	for s.Scan() {
		var entry map[string]any
		if err := json.Unmarshal(s.Bytes(), &entry); err != nil {
			continue
		}

		ts, _ := entry["timestamp"].(string)

		entryType, _ := entry["type"].(string)
		var produced []TextChunk

		switch entryType {
		case "response_item":
			produced = parseResponseItem(entry, path, ts)
		case "event_msg":
			produced = parseEventMsg(entry, path, ts)
		case "input_item":
			produced = parseInputItem(entry, path, ts)
		}

		if len(produced) > 0 {
			messageCount++
			chunks = append(chunks, produced...)
		}
	}

	if err := s.Err(); err != nil {
		return chunks, messageCount, err
	}
	return chunks, messageCount, nil
}

// parseResponseItem handles entries with type "response_item".
func parseResponseItem(entry map[string]any, path, ts string) []TextChunk {
	payload, ok := entry["payload"].(map[string]any)
	if !ok {
		return nil
	}

	payloadType, _ := payload["type"].(string)
	switch payloadType {
	case "message", "agent_message":
		return codexExtractContentText(payload, path, ts)
	case "function_call":
		return parseFunctionCall(payload, path, ts)
	case "function_call_output":
		return codexExtractStringField(payload, "output", path, ts)
	case "custom_tool_call":
		return codexExtractStringField(payload, "input", path, ts)
	case "custom_tool_call_output":
		return codexExtractStringField(payload, "output", path, ts)
	}
	return nil
}

// parseEventMsg handles entries with type "event_msg".
func parseEventMsg(entry map[string]any, path, ts string) []TextChunk {
	payload, ok := entry["payload"].(map[string]any)
	if !ok {
		return nil
	}

	payloadType, _ := payload["type"].(string)
	if payloadType != "user_message" {
		return nil
	}

	// Try payload.message first, then payload.text
	var chunks []TextChunk
	if msg, ok := payload["message"].(string); ok && msg != "" {
		chunks = append(chunks, TextChunk{
			Text:        msg,
			Source:      "codex",
			SessionFile: path,
			Timestamp:   ts,
		})
	}
	if text, ok := payload["text"].(string); ok && text != "" {
		chunks = append(chunks, TextChunk{
			Text:        text,
			Source:      "codex",
			SessionFile: path,
			Timestamp:   ts,
		})
	}
	return chunks
}

// parseInputItem handles entries with type "input_item".
func parseInputItem(entry map[string]any, path, ts string) []TextChunk {
	payload, ok := entry["payload"].(map[string]any)
	if !ok {
		return nil
	}

	payloadType, _ := payload["type"].(string)
	if payloadType != "message" {
		return nil
	}

	return codexExtractContentText(payload, path, ts)
}

// codexExtractContentText iterates payload.content[] and extracts text from
// blocks with type "input_text" or "output_text".
func codexExtractContentText(payload map[string]any, path, ts string) []TextChunk {
	content, ok := payload["content"].([]any)
	if !ok {
		return nil
	}

	var chunks []TextChunk
	for _, item := range content {
		block, ok := item.(map[string]any)
		if !ok {
			continue
		}
		blockType, _ := block["type"].(string)
		if blockType == "input_text" || blockType == "output_text" || blockType == "text" {
			if text, ok := block["text"].(string); ok && text != "" {
				chunks = append(chunks, TextChunk{
					Text:        text,
					Source:      "codex",
					SessionFile: path,
					Timestamp:   ts,
				})
			}
		}
	}
	return chunks
}

// parseFunctionCall handles payload.type == "function_call". The arguments
// field is a JSON-encoded string that needs double-parsing to extract the cmd.
func parseFunctionCall(payload map[string]any, path, ts string) []TextChunk {
	argsStr, ok := payload["arguments"].(string)
	if !ok || argsStr == "" {
		return nil
	}

	var args map[string]any
	if err := json.Unmarshal([]byte(argsStr), &args); err != nil {
		// If it fails to parse as JSON, treat the raw string as text
		return []TextChunk{{
			Text:        argsStr,
			Source:      "codex",
			SessionFile: path,
			Timestamp:   ts,
		}}
	}

	// Extract all string values from the arguments map (cmd, code, input, content, script, etc.)
	var chunks []TextChunk
	for _, v := range args {
		if s, ok := v.(string); ok && s != "" {
			chunks = append(chunks, TextChunk{
				Text:        s,
				Source:      "codex",
				SessionFile: path,
				Timestamp:   ts,
			})
		}
	}
	return chunks
}

// codexExtractStringField extracts a single string field from payload and
// returns it as a TextChunk.
func codexExtractStringField(payload map[string]any, field, path, ts string) []TextChunk {
	val, ok := payload[field].(string)
	if !ok || val == "" {
		return nil
	}
	return []TextChunk{{
		Text:        val,
		Source:      "codex",
		SessionFile: path,
		Timestamp:   ts,
	}}
}
