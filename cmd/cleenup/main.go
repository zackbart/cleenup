package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"cleenup/internal/model"
	"cleenup/internal/redactor"
	"cleenup/internal/report"
	"cleenup/internal/scanner"
	"cleenup/internal/state"
)

var version = "0.1.3"

func main() {
	root := &cobra.Command{
		Use:     "cleenup",
		Short:   "Scan Claude Code and Codex logs for leaked secrets",
		Long:    "Scans ~/.claude and ~/.codex session logs for API keys, tokens, passwords, and other secrets using TruffleHog, entropy analysis, and optional local LLM classification.",
		Version: version,
	}

	// scan command
	scanCmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan logs for secrets",
		RunE:  runScan,
	}
	scanCmd.Flags().Bool("deep", false, "Enable LM Studio model for enhanced detection")
	scanCmd.Flags().Int("port", 1234, "LM Studio API port")
	scanCmd.Flags().String("model", "", "LM Studio model name (auto-detects if empty)")
	scanCmd.Flags().StringP("output", "o", "", "Output report path (default: ~/.cleenup/report.json)")
	scanCmd.Flags().IntP("limit", "n", 0, "Max number of session files to scan (0 = all)")
	scanCmd.Flags().Bool("force", false, "Ignore state and rescan all files")

	// redact command
	redactCmd := &cobra.Command{
		Use:   "redact",
		Short: "Redact secrets found by scan",
		RunE:  runRedact,
	}
	redactCmd.Flags().Bool("dry-run", true, "Show what would be redacted without changing files")
	redactCmd.Flags().Bool("apply", false, "Actually redact secrets in-place")
	redactCmd.Flags().Bool("verify", false, "After applying redactions, re-scan affected files to confirm no secrets survived")
	redactCmd.Flags().String("report", "", "Path to scan report (default: ~/.cleenup/report.json)")

	root.AddCommand(scanCmd, redactCmd)

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

func runScan(cmd *cobra.Command, args []string) error {
	deep, _ := cmd.Flags().GetBool("deep")
	port, _ := cmd.Flags().GetInt("port")
	modelName, _ := cmd.Flags().GetString("model")
	output, _ := cmd.Flags().GetString("output")
	force, _ := cmd.Flags().GetBool("force")

	if output == "" {
		home, _ := os.UserHomeDir()
		output = home + "/.cleenup/report.json"
	}

	var mc *model.Client
	if deep {
		mc = model.NewClient(port, modelName)
		if err := mc.CheckConnection(); err != nil {
			return fmt.Errorf("LM Studio not reachable on port %d: %w\nStart LM Studio and load a model, then retry", port, err)
		}
		fmt.Printf("  LM Studio connected: %s\n\n", mc.ModelName())
	}

	limit, _ := cmd.Flags().GetInt("limit")

	// Load state
	st, err := state.Load(state.DefaultPath())
	if err != nil {
		fmt.Printf("  Warning: could not load state: %v (starting fresh)\n", err)
		st, _ = state.Load(state.DefaultPath())
	}

	s := scanner.New(mc)
	s.Limit = limit
	s.Force = force
	s.State = st

	rpt, err := s.Scan()
	if err != nil {
		return err
	}

	home, _ := os.UserHomeDir()
	if err := os.MkdirAll(home+"/.cleenup", 0o755); err != nil {
		return err
	}
	if err := rpt.SaveJSON(output); err != nil {
		return fmt.Errorf("failed to save report: %w", err)
	}

	// Save state after successful scan
	if err := st.Save(); err != nil {
		fmt.Printf("  Warning: could not save state: %v\n", err)
	}

	rpt.PrintSummary()
	fmt.Printf("\n  Report saved to %s\n", output)

	if len(rpt.Findings) > 0 {
		fmt.Printf("\n  Run `cleenup redact --dry-run` to preview redactions\n")
		fmt.Printf("  Run `cleenup redact --apply` to redact in-place\n")
		os.Exit(1)
	}
	return nil
}

func runRedact(cmd *cobra.Command, args []string) error {
	apply, _ := cmd.Flags().GetBool("apply")
	verify, _ := cmd.Flags().GetBool("verify")
	reportPath, _ := cmd.Flags().GetString("report")

	if reportPath == "" {
		home, _ := os.UserHomeDir()
		reportPath = home + "/.cleenup/report.json"
	}

	rpt, err := report.LoadJSON(reportPath)
	if err != nil {
		return fmt.Errorf("failed to load report: %w\nRun `cleenup scan` first", err)
	}

	r := redactor.New(rpt, apply)
	redactedFiles, err := r.Run()
	if err != nil {
		return err
	}

	// Update state for redacted files (only if --apply)
	if apply && len(redactedFiles) > 0 {
		st, stErr := state.Load(state.DefaultPath())
		if stErr == nil {
			for _, f := range redactedFiles {
				st.MarkRedacted(f)
			}
			if saveErr := st.Save(); saveErr != nil {
				fmt.Printf("  Warning: could not save state: %v\n", saveErr)
			}
		}
	}

	// Post-redaction verification scan
	if verify && apply && len(redactedFiles) > 0 {
		fmt.Println()
		fmt.Println("  Verifying redactions...")

		// Re-scan only the redacted files using built-in detection
		var surviving []report.Finding
		for _, filePath := range redactedFiles {
			source := "unknown"
			if strings.Contains(filePath, "/.claude/") {
				source = "claude"
			} else if strings.Contains(filePath, "/.codex/") {
				source = "codex"
			}

			var chunks []scanner.TextChunk
			var parseErr error

			switch {
			case source == "claude" && strings.HasSuffix(filePath, "history.jsonl"):
				chunks, _, parseErr = scanner.ParseClaudeHistoryFile(filePath)
			case source == "claude":
				chunks, _, parseErr = scanner.ParseClaudeFile(filePath)
			case source == "codex" && strings.HasSuffix(filePath, "history.jsonl"):
				chunks, _, parseErr = scanner.ParseCodexHistoryFile(filePath)
			default:
				chunks, _, parseErr = scanner.ParseCodexFile(filePath)
			}

			if parseErr != nil {
				fmt.Printf("  Warning: could not parse %s for verification: %v\n", filePath, parseErr)
				continue
			}

			for _, chunk := range chunks {
				surviving = append(surviving, scanner.Detect(chunk)...)
				surviving = append(surviving, scanner.DetectEntropy(chunk)...)
			}
		}

		if len(surviving) == 0 {
			fmt.Println("  Verification passed: no secrets found in redacted files")
		} else {
			fmt.Printf("  WARNING: %d secret(s) survived redaction:\n", len(surviving))
			for _, f := range surviving {
				masked := f.MatchedText
				if len(masked) > 20 {
					masked = masked[:6] + "..." + masked[len(masked)-4:]
				}
				fmt.Printf("    [%s] %s in %s\n", f.PatternName, masked, f.SessionFile)
			}
			fmt.Println("  Re-run `cleenup scan --force` then `cleenup redact --apply --verify` to catch remaining secrets")
		}
	}

	return nil
}
