package scanner

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"

	"cleenup/internal/report"
)

// trufflehogFinding represents a single finding from TruffleHog's JSON output.
type trufflehogFinding struct {
	SourceMetadata struct {
		Data struct {
			Filesystem struct {
				File string `json:"file"`
				Line int    `json:"line"`
			} `json:"Filesystem"`
		} `json:"Data"`
	} `json:"SourceMetadata"`
	DetectorName        string `json:"DetectorName"`
	DetectorDescription string `json:"DetectorDescription"`
	Verified            bool   `json:"Verified"`
	Raw                 string `json:"Raw"`
	Redacted            string `json:"Redacted"`
}

// TruffleHogAvailable checks if trufflehog is installed in PATH.
func TruffleHogAvailable() bool {
	_, err := exec.LookPath("trufflehog")
	return err == nil
}

// RunTruffleHog shells out to trufflehog and parses the JSON output into findings.
// It scans the provided directories (e.g., ~/.claude, ~/.codex).
func RunTruffleHog(dirs []string) ([]report.Finding, error) {
	args := []string{"filesystem"}
	args = append(args, dirs...)
	args = append(args, "--json", "--no-update")

	cmd := exec.Command("trufflehog", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("creating trufflehog stdout pipe: %w", err)
	}
	cmd.Stderr = nil // suppress stderr

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("starting trufflehog: %w", err)
	}

	var findings []report.Finding
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, 1024*1024), 10*1024*1024) // 10MB max line

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var thf trufflehogFinding
		if err := json.Unmarshal([]byte(line), &thf); err != nil {
			continue // skip malformed lines
		}

		filePath := thf.SourceMetadata.Data.Filesystem.File
		if filePath == "" || thf.Raw == "" {
			continue
		}

		// Normalize path to handle symlinks (e.g., /var vs /private/var on macOS)
		if resolved, err := filepath.EvalSymlinks(filePath); err == nil {
			filePath = resolved
		}

		// Determine source from file path
		source := "unknown"
		if strings.Contains(filePath, "/.claude/") {
			source = "claude"
		} else if strings.Contains(filePath, "/.codex/") {
			source = "codex"
		}

		findings = append(findings, report.Finding{
			Source:         source,
			SessionFile:    filePath,
			PatternName:    thf.DetectorName,
			MatchedText:    thf.Raw,
			Context:        thf.DetectorDescription,
			Layer:          report.LayerRegex, // TruffleHog is pattern-based
			Verified:       thf.Verified,
			DetectorSource: "trufflehog",
		})
	}

	// Wait for trufflehog to exit — exit code 0 means no findings,
	// non-zero can mean findings were found (exit 183) or an error.
	_ = cmd.Wait()

	return findings, nil
}
