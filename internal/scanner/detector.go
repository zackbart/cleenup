package scanner

import (
	"regexp"
	"strings"

	"cleenup/internal/report"
)

// falsePositiveValues are values that should never be flagged as secrets.
var falsePositiveValues = map[string]bool{
	"true":        true,
	"false":       true,
	"null":        true,
	"undefined":   true,
	"none":        true,
	"yes":         true,
	"no":          true,
	"enabled":     true,
	"disabled":    true,
	"localhost":   true,
	"127.0.0.1":   true,
	"0.0.0.0":     true,
	"production":  true,
	"development": true,
	"staging":     true,
	"test":        true,
}

// falsePositivePrefixPattern matches placeholder / template values that are
// not real secrets.
var falsePositivePrefixPattern = regexp.MustCompile(
	`(?i)^(your[_\-]|xxx|placeholder|changeme|CHANGE|TODO|FIXME|<)`,
)

// TextChunk represents a block of text to scan for secrets.
type TextChunk struct {
	Text        string
	Source      string // "claude" or "codex"
	SessionFile string
	Timestamp   string
}

// Detect scans a TextChunk for secrets using regex patterns and environment
// variable assignment analysis. It returns all findings.
func Detect(chunk TextChunk) []report.Finding {
	var findings []report.Finding

	text := chunk.Text

	// ── Pass 1: known secret patterns ────────────────────────────────
	for _, sp := range secretPatterns {
		locs := sp.Pattern.FindAllStringIndex(text, -1)
		for _, loc := range locs {
			matched := text[loc[0]:loc[1]]
			context := extractContext(text, loc[0], loc[1], 40)
			if isFalsePositivePattern(matched, context) {
				continue
			}
			findings = append(findings, report.Finding{
				Source:      chunk.Source,
				SessionFile: chunk.SessionFile,
				PatternName: sp.Name,
				MatchedText: matched,
				Context:     context,
				Timestamp:   chunk.Timestamp,
				Layer:       report.LayerRegex,
			})
		}
	}

	// ── Pass 2: environment variable assignments ─────────────────────
	envMatches := envAssignmentPattern.FindAllStringSubmatchIndex(text, -1)
	for _, idx := range envMatches {
		// Group 1: variable name, Group 2: value
		varName := text[idx[2]:idx[3]]
		value := text[idx[4]:idx[5]]

		if !isSensitiveVar(varName) {
			continue
		}
		if isFalsePositive(value) {
			continue
		}

		context := extractContext(text, idx[0], idx[1], 40)
		findings = append(findings, report.Finding{
			Source:      chunk.Source,
			SessionFile: chunk.SessionFile,
			PatternName: "Sensitive env var: " + varName,
			MatchedText: value,
			Context:     context,
			Timestamp:   chunk.Timestamp,
			Layer:       report.LayerRegex,
		})
	}

	return findings
}

// isSensitiveVar returns true if varName is in the sensitiveVarNames set or
// contains one of the sensitiveSubstrings.
func isSensitiveVar(varName string) bool {
	if sensitiveVarNames[varName] {
		return true
	}
	upper := strings.ToUpper(varName)
	for _, sub := range sensitiveSubstrings {
		if strings.Contains(upper, sub) {
			return true
		}
	}
	return false
}

// isFalsePositive returns true if value looks like a placeholder, template
// variable, or other non-secret string.
func isFalsePositive(value string) bool {
	lower := strings.ToLower(value)
	if falsePositiveValues[lower] {
		return true
	}
	if strings.HasPrefix(value, "${") ||
		strings.HasPrefix(value, "$(") ||
		strings.HasPrefix(value, "$") ||
		strings.HasPrefix(value, "process.env") ||
		strings.HasPrefix(value, "os.environ") ||
		strings.HasPrefix(value, "os.getenv") ||
		strings.HasPrefix(value, "[REDACTED") {
		return true
	}
	if falsePositivePrefixPattern.MatchString(value) {
		return true
	}
	// Template/example values like sk_live_your_key, pk_test_example
	if strings.HasPrefix(lower, "your_") || strings.HasPrefix(lower, "your-") ||
		strings.HasPrefix(lower, "dummy") || strings.HasPrefix(lower, "sample") ||
		strings.HasPrefix(lower, "test_") || strings.HasPrefix(lower, "example") ||
		lower == "example" {
		return true
	}
	// Localhost/placeholder connection strings and paths are not secrets
	if strings.Contains(lower, "localhost") ||
		strings.Contains(lower, "127.0.0.1") ||
		strings.Contains(lower, "user:pass@") ||
		strings.Contains(lower, "username:password@") ||
		strings.HasPrefix(value, "/api/") ||
		strings.HasPrefix(value, "/v1/") ||
		strings.HasPrefix(value, "/v2/") {
		return true
	}
	// Variable references (import.meta.env.X, process.env.X) are not secrets
	if strings.HasPrefix(value, "import.meta.env") {
		return true
	}
	// Values that are clearly identifiers/constants, not secrets
	// (e.g., "school_refresh_token", "oauth_state:", "user.password_change")
	if strings.HasPrefix(lower, "oauth_") ||
		value == lower && !strings.ContainsAny(value, "0123456789@:/") {
		// All-lowercase with no digits/special chars is likely a constant name, not a secret
		return true
	}
	// Already-redacted Sentry DSNs (xxx@oyyy patterns from prior runs)
	if strings.Contains(value, "xxx@") || strings.Contains(value, "...@") {
		return true
	}
	return false
}

// isFalsePositivePattern returns true if a regex pattern match is actually
// inside a code snippet, documentation example, or other non-secret context.
func isFalsePositivePattern(matched, context string) bool {
	// Pattern strings inside regex definitions or code examples
	if strings.Contains(context, "r'"+matched) ||
		strings.Contains(context, "r\""+matched) ||
		strings.Contains(context, "regexp.MustCompile") ||
		strings.Contains(context, "re.compile") ||
		strings.Contains(context, `\`+matched) ||
		strings.Contains(context, ", \""+matched[:10]) {
		return true
	}
	// Documentation/example connection strings with placeholder credentials
	lower := strings.ToLower(matched)
	if strings.Contains(lower, "user:pass@") ||
		strings.Contains(lower, "username:password@") ||
		strings.Contains(lower, "dev:password@localhost") ||
		strings.Contains(lower, "admin:admin@") {
		return true
	}
	return false
}

// extractContext returns a substring of text around [start, end) with up to
// pad characters on each side.
func extractContext(text string, start, end, pad int) string {
	ctxStart := start - pad
	if ctxStart < 0 {
		ctxStart = 0
	}
	ctxEnd := end + pad
	if ctxEnd > len(text) {
		ctxEnd = len(text)
	}
	return text[ctxStart:ctxEnd]
}
