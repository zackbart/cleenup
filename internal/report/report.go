package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type DetectionLayer string

const (
	LayerRegex   DetectionLayer = "regex"
	LayerEntropy DetectionLayer = "entropy"
	LayerModel   DetectionLayer = "model"
)

type Finding struct {
	Source         string         `json:"source"`       // "claude" or "codex"
	SessionFile    string         `json:"session_file"`
	PatternName    string         `json:"pattern_name"`
	MatchedText    string         `json:"matched_text"`
	Context        string         `json:"context"`
	Timestamp      string         `json:"timestamp,omitempty"`
	Layer          DetectionLayer `json:"layer"`
	Verified       bool           `json:"verified,omitempty"`
	DetectorSource string         `json:"detector_source"` // "trufflehog", "entropy", "model", or "builtin"
}

type ScanStats struct {
	ClaudeSessions int `json:"claude_sessions"`
	CodexSessions  int `json:"codex_sessions"`
	ClaudeMessages int `json:"claude_messages"`
	CodexMessages  int `json:"codex_messages"`
}

type Report struct {
	Stats    ScanStats `json:"stats"`
	Findings []Finding `json:"findings"`
}

func NewReport() *Report {
	return &Report{
		Findings: make([]Finding, 0),
	}
}

func (r *Report) SaveJSON(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func LoadJSON(path string) (*Report, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var rpt Report
	if err := json.Unmarshal(data, &rpt); err != nil {
		return nil, err
	}
	return &rpt, nil
}

func maskValue(s string) string {
	if len(s) <= 10 {
		return s[:3] + "***"
	}
	return s[:6] + "..." + s[len(s)-4:]
}

func (r *Report) PrintSummary() {
	fmt.Println()
	fmt.Println(strings.Repeat("=", 70))
	fmt.Println("  cleenup — Secret Scanner Report")
	fmt.Println(strings.Repeat("=", 70))
	fmt.Println()
	fmt.Printf("  Scanned:\n")
	fmt.Printf("    Claude sessions: %d (%d messages)\n", r.Stats.ClaudeSessions, r.Stats.ClaudeMessages)
	fmt.Printf("    Codex sessions:  %d (%d messages)\n", r.Stats.CodexSessions, r.Stats.CodexMessages)
	fmt.Println()

	if len(r.Findings) == 0 {
		fmt.Println("  No secrets found. You're clean!")
		fmt.Println()
		return
	}

	// Deduplicate by matched_text + pattern_name
	type key struct{ pattern, text string }
	seen := make(map[key]bool)
	var unique []Finding
	for _, f := range r.Findings {
		k := key{f.PatternName, f.MatchedText}
		if !seen[k] {
			seen[k] = true
			unique = append(unique, f)
		}
	}

	fmt.Printf("  Found %d unique secrets (%d total occurrences)\n", len(unique), len(r.Findings))
	fmt.Println(strings.Repeat("-", 70))
	fmt.Println()

	// Group by pattern
	byPattern := make(map[string][]Finding)
	for _, f := range unique {
		byPattern[f.PatternName] = append(byPattern[f.PatternName], f)
	}

	patterns := make([]string, 0, len(byPattern))
	for p := range byPattern {
		patterns = append(patterns, p)
	}
	sort.Strings(patterns)

	for _, pattern := range patterns {
		findings := byPattern[pattern]
		fmt.Printf("  [%s] — %d unique match(es)\n", pattern, len(findings))
		for _, f := range findings {
			masked := maskValue(f.MatchedText)
			session := filepath.Base(f.SessionFile)
			if len(session) > 40 {
				session = session[:40]
			}
			verifiedTag := ""
			if f.Verified {
				verifiedTag = " [VERIFIED]"
			}
			fmt.Printf("    %s%s\n", masked, verifiedTag)
			detSrc := f.DetectorSource
			if detSrc == "" {
				detSrc = string(f.Layer)
			}
			fmt.Printf("      source: %s | detector: %s | layer: %s | session: %s\n", f.Source, detSrc, f.Layer, session)
			if f.Timestamp != "" {
				fmt.Printf("      time: %s\n", f.Timestamp)
			}
		}
		fmt.Println()
	}

	fmt.Println(strings.Repeat("-", 70))
	fmt.Println("  Run `cleenup redact --dry-run` to preview redactions")
	fmt.Println("  Run `cleenup redact --apply` to redact in-place")
	fmt.Println(strings.Repeat("=", 70))
}
