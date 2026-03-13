package redactor

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"cleenup/internal/report"
)

type Redactor struct {
	report *report.Report
	apply  bool
}

func New(rpt *report.Report, apply bool) *Redactor {
	return &Redactor{report: rpt, apply: apply}
}

func maskValue(s string) string {
	if len(s) <= 10 {
		return s[:3] + "***"
	}
	return s[:6] + "..." + s[len(s)-4:]
}

// Run executes redaction and returns the list of files that were actually modified.
func (r *Redactor) Run() ([]string, error) {
	// 1. Group findings by SessionFile
	byFile := make(map[string][]report.Finding)
	for _, f := range r.report.Findings {
		byFile[f.SessionFile] = append(byFile[f.SessionFile], f)
	}

	// 2. Print header
	if r.apply {
		fmt.Println("APPLYING — redacting secrets in-place")
	} else {
		fmt.Println("DRY RUN — showing what would be redacted")
	}
	fmt.Println()

	totalFiles := 0
	totalRedactions := 0
	var redactedFiles []string

	// 3. Process each file
	for filePath, findings := range byFile {
		// a. Read the entire file content
		data, err := os.ReadFile(filePath)
		if err != nil {
			fmt.Printf("  WARNING: could not read %s: %v\n", filePath, err)
			continue
		}
		content := string(data)
		fileRedactions := 0

		// b. Deduplicate findings by MatchedText (keep the most specific pattern name)
		//    and sort longest first so a longer match isn't partially eaten by a shorter one
		deduped := dedupByText(findings)
		sort.Slice(deduped, func(i, j int) bool {
			return len(deduped[i].MatchedText) > len(deduped[j].MatchedText)
		})

		// c. Replace each finding — both raw and JSON-escaped forms
		for _, f := range deduped {
			replacement := "REDACTED_BY_CLEENUP"
			before := content

			// Replace the raw form
			content = strings.ReplaceAll(content, f.MatchedText, replacement)

			// Also replace the JSON-escaped form. Secrets with special characters
			// (quotes, backslashes, newlines) are stored JSON-encoded in JSONL files.
			// json.Marshal produces the escaped string with surrounding quotes.
			escaped, err := json.Marshal(f.MatchedText)
			if err == nil {
				// Strip the surrounding quotes from json.Marshal output
				escapedStr := string(escaped[1 : len(escaped)-1])
				if escapedStr != f.MatchedText {
					content = strings.ReplaceAll(content, escapedStr, replacement)
				}
			}

			if content != before {
				fileRedactions++
			}
		}

		if fileRedactions == 0 {
			continue
		}

		totalFiles++
		totalRedactions += fileRedactions

		if r.apply {
			// d. Write to temp file and atomically replace
			dir := filepath.Dir(filePath)
			tmpPath := filepath.Join(dir, filepath.Base(filePath)+".tmp")

			if err := os.WriteFile(tmpPath, []byte(content), 0o600); err != nil {
				fmt.Printf("  WARNING: could not write temp file for %s: %v\n", filePath, err)
				continue
			}
			if err := os.Rename(tmpPath, filePath); err != nil {
				fmt.Printf("  WARNING: could not rename temp file for %s: %v\n", filePath, err)
				continue
			}
			fmt.Printf("  %s — %d redaction(s) applied\n", filePath, fileRedactions)
			redactedFiles = append(redactedFiles, filePath)
		} else {
			// e. Dry-run output — uses deduped list for consistent counts
			fmt.Printf("  %s\n", filePath)
			for _, f := range deduped {
				masked := maskValue(f.MatchedText)
				replacement := "REDACTED_BY_CLEENUP"
				fmt.Printf("    would redact: %s → %s\n", masked, replacement)
			}
		}
	}

	// 4. Print summary
	fmt.Println()
	if r.apply {
		fmt.Printf("Summary: %d file(s) affected, %d redaction(s) applied\n", totalFiles, totalRedactions)
	} else {
		fmt.Printf("Summary: %d file(s) affected, %d redaction(s) would be applied\n", totalFiles, totalRedactions)
	}

	return redactedFiles, nil
}

// dedupByText keeps one finding per unique MatchedText, preferring more specific
// pattern names (e.g., "Stripe live secret key" over "High entropy string").
func dedupByText(findings []report.Finding) []report.Finding {
	seen := make(map[string]report.Finding)
	for _, f := range findings {
		existing, ok := seen[f.MatchedText]
		if !ok || isBetterName(f.PatternName, existing.PatternName) {
			seen[f.MatchedText] = f
		}
	}
	result := make([]report.Finding, 0, len(seen))
	for _, f := range seen {
		result = append(result, f)
	}
	return result
}

// isBetterName returns true if newName is more specific than oldName.
// Prefers named patterns over generic entropy/env var labels.
func isBetterName(newName, oldName string) bool {
	oldGeneric := strings.HasPrefix(oldName, "High entropy") || strings.HasPrefix(oldName, "Sensitive env var:")
	newGeneric := strings.HasPrefix(newName, "High entropy") || strings.HasPrefix(newName, "Sensitive env var:")
	if !newGeneric && oldGeneric {
		return true
	}
	return false
}
