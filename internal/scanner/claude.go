package scanner

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

// WalkClaudeFiles walks ~/.claude/projects/ recursively and also includes
// ~/.claude/history.jsonl. Returns all .jsonl file paths.
func WalkClaudeFiles() ([]string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	var files []string

	// Include history file
	historyFile := filepath.Join(home, ".claude", "history.jsonl")
	if _, err := os.Stat(historyFile); err == nil {
		files = append(files, historyFile)
	}

	// Walk session logs
	root := filepath.Join(home, ".claude", "projects")
	if _, err := os.Stat(root); os.IsNotExist(err) {
		return files, nil
	}

	err = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // skip inaccessible entries
		}
		if !info.IsDir() && strings.HasSuffix(path, ".jsonl") {
			files = append(files, path)
		}
		return nil
	})
	return files, err
}

// ParseClaudeHistoryFile reads the Claude history.jsonl file. Each line has
// a "display" field (user prompt text) and optional "pastedContents".
func ParseClaudeHistoryFile(path string) (chunks []TextChunk, messageCount int, err error) {
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

		// The "display" field contains the user's prompt text
		if display, ok := entry["display"].(string); ok && display != "" {
			chunks = append(chunks, TextChunk{
				Text:        display,
				Source:      "claude",
				SessionFile: path,
				Timestamp:   "",
			})
		}

		// "pastedContents" is a map of filename → content
		if pasted, ok := entry["pastedContents"].(map[string]any); ok {
			for _, v := range pasted {
				if text, ok := v.(string); ok && text != "" {
					chunks = append(chunks, TextChunk{
						Text:        text,
						Source:      "claude",
						SessionFile: path,
						Timestamp:   "",
					})
				}
			}
		}
	}

	if err := s.Err(); err != nil {
		return chunks, messageCount, err
	}
	return chunks, messageCount, nil
}

// ParseClaudeFile reads a JSONL session log and extracts all text chunks where
// secrets could appear. messageCount tracks user/assistant entries processed.
func ParseClaudeFile(path string) (chunks []TextChunk, messageCount int, err error) {
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
		switch entryType {
		case "user", "assistant":
			messageCount++
			chunks = append(chunks, extractMessageChunks(entry, path, ts)...)

			// Also check top-level toolUseResult.stdout
			if tur, ok := entry["toolUseResult"].(map[string]any); ok {
				if stdout, ok := tur["stdout"].(string); ok && stdout != "" {
					chunks = append(chunks, TextChunk{
						Text:        stdout,
						Source:      "claude",
						SessionFile: path,
						Timestamp:   ts,
					})
				}
			}

		case "progress":
			data, ok := entry["data"].(map[string]any)
			if !ok {
				continue
			}
			dataType, _ := data["type"].(string)
			switch dataType {
			case "bash_progress":
				if output, ok := data["output"].(string); ok && output != "" {
					chunks = append(chunks, TextChunk{
						Text:        output,
						Source:      "claude",
						SessionFile: path,
						Timestamp:   ts,
					})
				}
				if fullOutput, ok := data["fullOutput"].(string); ok && fullOutput != "" {
					chunks = append(chunks, TextChunk{
						Text:        fullOutput,
						Source:      "claude",
						SessionFile: path,
						Timestamp:   ts,
					})
				}
			case "agent_progress":
				// data.message.message.content — same nested structure as assistant messages
				if msg, ok := data["message"].(map[string]any); ok {
					if inner, ok := msg["message"].(map[string]any); ok {
						chunks = append(chunks, extractContentChunks(inner["content"], path, ts)...)
					}
				}
			}

		case "queue-operation":
			if content, ok := entry["content"].(string); ok && content != "" {
				chunks = append(chunks, TextChunk{
					Text:        content,
					Source:      "claude",
					SessionFile: path,
					Timestamp:   ts,
				})
			}
		}
	}

	if err := s.Err(); err != nil {
		return chunks, messageCount, err
	}
	return chunks, messageCount, nil
}

// extractMessageChunks pulls text from a user or assistant message entry.
func extractMessageChunks(entry map[string]any, path, ts string) []TextChunk {
	msg, ok := entry["message"].(map[string]any)
	if !ok {
		return nil
	}
	return extractContentChunks(msg["content"], path, ts)
}

// extractContentChunks handles the content field which can be a string or an
// array of content blocks.
func extractContentChunks(content any, path, ts string) []TextChunk {
	if content == nil {
		return nil
	}

	// content can be a plain string
	if s, ok := content.(string); ok {
		if s != "" {
			return []TextChunk{{Text: s, Source: "claude", SessionFile: path, Timestamp: ts}}
		}
		return nil
	}

	// content can be an array of content blocks
	arr, ok := content.([]any)
	if !ok {
		return nil
	}

	var chunks []TextChunk
	for _, item := range arr {
		block, ok := item.(map[string]any)
		if !ok {
			continue
		}
		chunks = append(chunks, extractBlock(block, path, ts)...)
	}
	return chunks
}

// extractBlock extracts text from a single content block based on its type.
func extractBlock(block map[string]any, path, ts string) []TextChunk {
	blockType, _ := block["type"].(string)

	mk := func(text string) TextChunk {
		return TextChunk{Text: text, Source: "claude", SessionFile: path, Timestamp: ts}
	}

	var chunks []TextChunk
	add := func(text string) {
		if text != "" {
			chunks = append(chunks, mk(text))
		}
	}

	switch blockType {
	case "text":
		if text, ok := block["text"].(string); ok {
			add(text)
		}

	case "tool_use":
		input, ok := block["input"].(map[string]any)
		if !ok {
			break
		}
		// Bash tool — command field
		if cmd, ok := input["command"].(string); ok {
			add(cmd)
		}
		// Write tool — content field
		if content, ok := input["content"].(string); ok {
			add(content)
		}
		// Edit tool — old_string and new_string
		if old, ok := input["old_string"].(string); ok {
			add(old)
		}
		if ns, ok := input["new_string"].(string); ok {
			add(ns)
		}
		// Read tool — file_path
		if fp, ok := input["file_path"].(string); ok {
			add(fp)
		}

	case "tool_result":
		extractToolResult(block["content"], path, ts, &chunks)
	}

	return chunks
}

// extractToolResult handles the tool_result content field which can be a string
// or an array of objects with text fields.
func extractToolResult(content any, path, ts string, chunks *[]TextChunk) {
	if content == nil {
		return
	}

	if s, ok := content.(string); ok {
		if s != "" {
			*chunks = append(*chunks, TextChunk{Text: s, Source: "claude", SessionFile: path, Timestamp: ts})
		}
		return
	}

	arr, ok := content.([]any)
	if !ok {
		return
	}

	for _, item := range arr {
		obj, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if text, ok := obj["text"].(string); ok && text != "" {
			*chunks = append(*chunks, TextChunk{Text: text, Source: "claude", SessionFile: path, Timestamp: ts})
		}
	}
}
