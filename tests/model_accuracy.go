package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"cleenup/internal/model"
)

// expectedSecrets defines what each test file should find
var expectedSecrets = map[string][]string{
	"01_obvious_secrets.txt": {
		"sk_" + "live_TESTKEY00000000000000000",
		"sk-proj-abc123def456ghi789jkl012mno345pqr678",
		"R3allyS3cretP@ss!",
		"ghp_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8",
		"wJalrXUtnFEMI/K7MDENG/bPxRfiCYzzzKEY",
	},
	"02_inline_secrets.txt": {
		"sk-ant-api03-xK9mN2pQ5rT8vW1yB4dF7gJ0lO3sU6hA9cE2iM5nP8qR1tV4wX7zA0bD3fG6jK-abcdefgh",
		"whsec_MhdbMVxK7P2NqR9sT4uW1xY3zA5bC7dE",
		"x8Km$nP2qR!vT4w",
	},
	"03_subtle_secrets.txt": {
		"mK9xP2nQ5rT8vW1yB4dF7gJ0lO3sU6hA",
		"Tr0ub4dor&3xCh@ng3M3N0w!",
		"clv_prod_9a8b7c6d5e4f3g2h1i0j",
		"a4f8e2d1c7b3a9f5e0d6c2b8a4f0e6d2c8b4a0f6e2d8c4b0a6f2e8d4c0b6a2f8",
	},
	"04_false_positives.txt": {
		// should be empty — nothing here is a real secret
	},
	"05_mixed_context.txt": {
		"re_7xKm9Np2Qr4St6Uv8Wx0Ya2Bc4De6Fg",
		"abc123def456",
		"myR3disP@ssw0rd",
	},
}

func main() {
	port := 1234
	mc := model.NewClient(port, "")
	if err := mc.CheckConnection(); err != nil {
		fmt.Printf("Error: %v\n", err)
		fmt.Println("Start LM Studio and load a model first.")
		os.Exit(1)
	}

	fmt.Printf("Model: %s\n", mc.ModelName())
	fmt.Println(strings.Repeat("=", 60))

	testDir := "tests"
	files, _ := filepath.Glob(filepath.Join(testDir, "*.txt"))
	sort.Strings(files)

	totalExpected := 0
	totalFound := 0
	totalFalsePos := 0
	totalMissed := 0

	for _, file := range files {
		basename := filepath.Base(file)
		expected := expectedSecrets[basename]

		data, err := os.ReadFile(file)
		if err != nil {
			fmt.Printf("Error reading %s: %v\n", file, err)
			continue
		}

		fmt.Printf("\n--- %s ---\n", basename)

		findings, err := mc.Classify(string(data))
		if err != nil {
			fmt.Printf("  Model error: %v\n", err)
			continue
		}

		// Pretty-print raw model response
		raw, _ := json.MarshalIndent(findings, "  ", "  ")
		fmt.Printf("  Model returned %d findings:\n  %s\n", len(findings), string(raw))

		// Score: check which expected secrets were found
		foundSet := make(map[string]bool)
		for _, f := range findings {
			foundSet[f.Value] = true
		}

		hits := 0
		missed := 0
		for _, exp := range expected {
			found := false
			for _, f := range findings {
				if strings.Contains(f.Value, exp) || strings.Contains(exp, f.Value) {
					found = true
					break
				}
			}
			if found {
				hits++
				fmt.Printf("  ✓ Found: %s\n", truncate(exp, 50))
			} else {
				missed++
				fmt.Printf("  ✗ Missed: %s\n", truncate(exp, 50))
			}
		}

		// Check for false positives (model found something not in expected)
		falsePos := 0
		for _, f := range findings {
			isExpected := false
			for _, exp := range expected {
				if strings.Contains(f.Value, exp) || strings.Contains(exp, f.Value) {
					isExpected = true
					break
				}
			}
			if !isExpected {
				falsePos++
				fmt.Printf("  ⚠ False positive: %s (%s)\n", truncate(f.Value, 50), f.Type)
			}
		}

		totalExpected += len(expected)
		totalFound += hits
		totalMissed += missed
		totalFalsePos += falsePos

		if len(expected) > 0 {
			fmt.Printf("  Score: %d/%d found, %d false positives\n", hits, len(expected), falsePos)
		} else {
			fmt.Printf("  Score: %d false positives (expected 0)\n", falsePos)
		}
	}

	fmt.Println()
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("TOTAL: %d/%d secrets found (%.0f%%), %d missed, %d false positives\n",
		totalFound, totalExpected,
		float64(totalFound)/float64(max(totalExpected, 1))*100,
		totalMissed, totalFalsePos)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
