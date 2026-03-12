package scanner

import (
	"fmt"
	"math"
	"regexp"
	"strings"
	"unicode"

	"cleenup/internal/report"
)

// tokenSplitter splits text into tokens at whitespace and common delimiters.
var tokenSplitter = regexp.MustCompile(`[^\s"'` + "`" + `=;,:{}\[\]()]+`)

// base64HexPattern identifies strings that look like base64 or hex-encoded values.
var base64HexPattern = regexp.MustCompile(`^[a-zA-Z0-9+/=_\-]{20,}$`)

// uuidPattern matches UUID-formatted strings (8-4-4-4-12 hex pattern).
var uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// allLowerAlpha matches tokens composed entirely of lowercase letters.
var allLowerAlpha = regexp.MustCompile(`^[a-z]+$`)

// hexOnly matches tokens composed entirely of hex characters.
var hexOnly = regexp.MustCompile(`^[0-9a-fA-F]+$`)

// knownNonSecretPrefixes are prefixes of high-entropy strings that are internal
// identifiers from Claude, Codex, and API systems — not secrets.
var knownNonSecretPrefixes = []string{
	"toolu_",     // Claude tool use IDs
	"req_",       // API request IDs
	"msg_",       // API message IDs
	"resp_",      // API response IDs
	"chatcmpl-",  // OpenAI chat completion IDs
	"call_",      // Function call IDs
	"run_",       // Run IDs
	"step_",      // Step IDs
	"asst_",      // Assistant IDs
	"thread_",    // Thread IDs
	"file-",      // File IDs
	"org-",       // Org IDs
	"MII",        // X.509 certificate body (not the header, just the base64 body)
	"data:image", // Data URIs
	"sha256-",    // SRI hashes
	"sha512-",    // SRI hashes
	"sha1-",      // Git/hash references
	"agent-a",    // Claude agent IDs
	"acompact-",  // Claude compact IDs
	"[REDACTED",  // Already-redacted markers from previous cleenup runs
}

func isKnownNonSecretPrefix(token string) bool {
	for _, prefix := range knownNonSecretPrefixes {
		if strings.HasPrefix(token, prefix) {
			return true
		}
	}
	return false
}

// shannonEntropy calculates the Shannon entropy of a string in bits per character.
func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	freq := make(map[byte]int)
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}

	length := float64(len(s))
	entropy := 0.0
	for _, count := range freq {
		p := float64(count) / length
		entropy -= p * math.Log2(p)
	}

	return entropy
}

// DetectEntropy scans a TextChunk for high-entropy tokens that may be secrets.
func DetectEntropy(chunk TextChunk) []report.Finding {
	var findings []report.Finding

	tokens := tokenSplitter.FindAllStringIndex(chunk.Text, -1)

	for _, loc := range tokens {
		token := chunk.Text[loc[0]:loc[1]]

		// Skip short tokens — real secrets are usually 30+ chars
		if len(token) < 30 {
			continue
		}

		// Skip tokens that don't look like base64/hex
		if !base64HexPattern.MatchString(token) {
			continue
		}

		entropy := shannonEntropy(token)

		// Skip low-entropy tokens — 5.0 threshold reduces false positives
		// from crypto addresses, hashes, and non-secret identifiers
		if entropy < 5.0 {
			continue
		}

		// Skip common false positives

		// All lowercase letters — likely English words or paths
		if allLowerAlpha.MatchString(token) {
			continue
		}

		// UUID pattern
		if uuidPattern.MatchString(token) {
			continue
		}

		// Known non-secret prefixes from Claude/Codex/API internals
		if isKnownNonSecretPrefix(token) {
			continue
		}

		// File paths (contain / or start with docs/, src/, etc.)
		if strings.Contains(token, "/") {
			continue
		}

		// Git commit SHAs — exactly 40 hex chars
		if len(token) == 40 && hexOnly.MatchString(token) {
			continue
		}

		// Short hex strings that are likely hashes, not secrets (< 48 chars, pure hex)
		if len(token) <= 48 && hexOnly.MatchString(token) {
			continue
		}

		// Build context: 40 chars before and after the token
		contextStart := loc[0] - 40
		if contextStart < 0 {
			contextStart = 0
		}
		contextEnd := loc[1] + 40
		if contextEnd > len(chunk.Text) {
			contextEnd = len(chunk.Text)
		}

		// Remove newlines from context for cleaner output
		ctx := chunk.Text[contextStart:contextEnd]
		ctx = strings.Map(func(r rune) rune {
			if unicode.IsControl(r) && r != '\t' {
				return ' '
			}
			return r
		}, ctx)

		findings = append(findings, report.Finding{
			Source:      chunk.Source,
			SessionFile: chunk.SessionFile,
			PatternName: fmt.Sprintf("High entropy string (%.1f bits)", entropy),
			MatchedText: token,
			Context:     ctx,
			Timestamp:   chunk.Timestamp,
			Layer:       report.LayerEntropy,
		})
	}

	return findings
}
