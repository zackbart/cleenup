package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"cleenup/internal/model"
	"cleenup/internal/report"
	"cleenup/internal/state"
)

// Scanner orchestrates parallel scanning of Claude and Codex logs.
type Scanner struct {
	modelClient *model.Client // nil if --deep not used
	Limit       int           // max files to scan (0 = all)
	Force       bool          // ignore state, rescan everything
	State       *state.State  // scan state tracker (nil disables state)
}

// New creates a scanner. Pass nil for modelClient to disable deep scanning.
func New(mc *model.Client) *Scanner {
	return &Scanner{modelClient: mc}
}

type fileJob struct {
	path   string
	source string // "claude" or "codex"
}

type fileResult struct {
	findings     []report.Finding
	messageCount int
	source       string
	err          error
}

// Scan runs the full scan pipeline and returns a report.
func (s *Scanner) Scan() (*report.Report, error) {
	rpt := report.NewReport()

	// Collect all files
	fmt.Print("  Discovering log files...")

	claudeFiles, err := WalkClaudeFiles()
	if err != nil {
		return nil, fmt.Errorf("walking Claude files: %w", err)
	}
	codexFiles, err := WalkCodexFiles()
	if err != nil {
		return nil, fmt.Errorf("walking Codex files: %w", err)
	}

	fmt.Printf(" found %d Claude + %d Codex sessions\n", len(claudeFiles), len(codexFiles))

	// Apply limit — sort by modification time (newest first) and take the first N
	if s.Limit > 0 {
		sortByModTimeDesc(claudeFiles)
		sortByModTimeDesc(codexFiles)
		if len(claudeFiles) > s.Limit {
			claudeFiles = claudeFiles[:s.Limit]
		}
		if len(codexFiles) > s.Limit {
			codexFiles = codexFiles[:s.Limit]
		}
		fmt.Printf("  Limited to %d files (--limit %d)\n", len(claudeFiles)+len(codexFiles), s.Limit)
	}

	// Filter files using state (skip already-scanned unchanged files)
	if s.State != nil && !s.Force {
		var filteredClaude, filteredCodex []string
		skipped := 0
		for _, f := range claudeFiles {
			if s.State.ShouldScan(f) {
				filteredClaude = append(filteredClaude, f)
			} else {
				skipped++
			}
		}
		for _, f := range codexFiles {
			if s.State.ShouldScan(f) {
				filteredCodex = append(filteredCodex, f)
			} else {
				skipped++
			}
		}
		if skipped > 0 {
			fmt.Printf("  Skipped %d unchanged files (use --force to rescan)\n", skipped)
		}
		claudeFiles = filteredClaude
		codexFiles = filteredCodex
	}

	rpt.Stats.ClaudeSessions = len(claudeFiles)
	rpt.Stats.CodexSessions = len(codexFiles)
	totalFiles := len(claudeFiles) + len(codexFiles)

	if totalFiles == 0 {
		fmt.Println("  No log files found (or all up-to-date).")
		return rpt, nil
	}

	// ── Layer 1: TruffleHog or built-in patterns ──────────────────────
	var layer1Findings []report.Finding
	useTrufflehog := TruffleHogAvailable()

	if useTrufflehog {
		fmt.Println("  Layer 1: TruffleHog scanning...")
		// Build list of directories to scan
		scanDirs := trufflehogDirs()
		thFindings, err := RunTruffleHog(scanDirs)
		if err != nil {
			fmt.Printf("  Warning: TruffleHog error: %v\n", err)
			fmt.Println("  Falling back to built-in pattern matching...")
			useTrufflehog = false
		} else {
			// Filter TruffleHog findings to only include files we're scanning.
			// Normalize paths to handle symlinks (e.g., /var vs /private/var on macOS).
			fileSet := make(map[string]bool, totalFiles)
			for _, f := range claudeFiles {
				normalized := f
				if resolved, err := filepath.EvalSymlinks(f); err == nil {
					normalized = resolved
				}
				fileSet[normalized] = true
			}
			for _, f := range codexFiles {
				normalized := f
				if resolved, err := filepath.EvalSymlinks(f); err == nil {
					normalized = resolved
				}
				fileSet[normalized] = true
			}
			droppedByLimit := 0
			for _, f := range thFindings {
				if fileSet[f.SessionFile] {
					layer1Findings = append(layer1Findings, f)
				} else {
					droppedByLimit++
				}
			}
			fmt.Printf("  TruffleHog found %d secrets\n", len(layer1Findings))
			if droppedByLimit > 0 && s.Limit > 0 {
				fmt.Printf("  Warning: TruffleHog found %d additional secrets in files outside --limit range. Run without --limit to see all.\n", droppedByLimit)
			}
		}
	}

	if !useTrufflehog {
		fmt.Println("  TruffleHog not found. Install with: brew install trufflehog")
		fmt.Println("  Using built-in pattern matching only...")
	}

	// ── Parallel file processing (built-in regex fallback + entropy + model pre-filter) ──
	jobs := make(chan fileJob, totalFiles)
	for _, f := range claudeFiles {
		jobs <- fileJob{path: f, source: "claude"}
	}
	for _, f := range codexFiles {
		jobs <- fileJob{path: f, source: "codex"}
	}
	close(jobs)

	workers := runtime.NumCPU()
	if workers > totalFiles {
		workers = totalFiles
	}

	var (
		mu           sync.Mutex
		allFindings  []report.Finding
		allChunks    []model.ChunkForModel
		filesScanned atomic.Int64
		scannedPaths []string // for state tracking
	)

	fmt.Printf("  Scanning with %d workers...\n", workers)

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				var chunks []TextChunk
				var msgCount int
				var parseErr error

				switch {
				case job.source == "claude" && strings.HasSuffix(job.path, "history.jsonl"):
					chunks, msgCount, parseErr = ParseClaudeHistoryFile(job.path)
				case job.source == "claude":
					chunks, msgCount, parseErr = ParseClaudeFile(job.path)
				case job.source == "codex" && strings.HasSuffix(job.path, "history.jsonl"):
					chunks, msgCount, parseErr = ParseCodexHistoryFile(job.path)
				default:
					chunks, msgCount, parseErr = ParseCodexFile(job.path)
				}

				if parseErr != nil {
					mu.Lock()
					fmt.Printf("  Warning: error parsing %s: %v\n", job.path, parseErr)
					mu.Unlock()
				}

				var localFindings []report.Finding
				var localModelChunks []model.ChunkForModel

				for _, chunk := range chunks {
					// Built-in regex — always runs on parsed text chunks.
					// TruffleHog scans raw file bytes and may miss secrets
					// buried inside JSON-encoded strings. The JSONL parsers
					// extract the actual text, so built-in regex + env var
					// detection catches what TruffleHog can't reach.
					builtinFindings := Detect(chunk)
					for i := range builtinFindings {
						builtinFindings[i].DetectorSource = "builtin"
					}
					localFindings = append(localFindings, builtinFindings...)

					// Layer 2: Entropy (always runs)
					entropyFindings := DetectEntropy(chunk)
					for i := range entropyFindings {
						entropyFindings[i].DetectorSource = "entropy"
					}
					localFindings = append(localFindings, entropyFindings...)

					// Pre-filter for model if deep scan enabled
					if s.modelClient != nil && shouldSendToModel(chunk.Text) {
						localModelChunks = append(localModelChunks, model.ChunkForModel{
							Text:        chunk.Text,
							Source:      chunk.Source,
							SessionFile: chunk.SessionFile,
							Timestamp:   chunk.Timestamp,
						})
					}
				}

				mu.Lock()
				allFindings = append(allFindings, localFindings...)
				allChunks = append(allChunks, localModelChunks...)
				scannedPaths = append(scannedPaths, job.path)
				if job.source == "claude" {
					rpt.Stats.ClaudeMessages += msgCount
				} else {
					rpt.Stats.CodexMessages += msgCount
				}
				mu.Unlock()

				done := filesScanned.Add(1)
				if done%50 == 0 || done == int64(totalFiles) {
					fmt.Printf("\r  Progress: %d/%d files scanned", done, totalFiles)
				}
			}
		}()
	}

	wg.Wait()
	fmt.Println()

	// Merge Layer 1 (TruffleHog) + Layer 2 (entropy) + fallback regex findings
	allFindings = append(layer1Findings, allFindings...)

	if useTrufflehog {
		fmt.Printf("  TruffleHog + builtin + entropy: found %d potential secrets\n", len(allFindings))
	} else {
		fmt.Printf("  Builtin + entropy: found %d potential secrets\n", len(allFindings))
	}

	// Layer 3: Model classification (if --deep)
	if s.modelClient != nil && len(allChunks) > 0 {
		fmt.Printf("  Deep scan: sending %d suspicious chunks to %s...\n", len(allChunks), s.modelClient.ModelName())
		modelFindings := s.modelClient.ClassifyChunks(allChunks, func(done, total int) {
			if done%10 == 0 || done == total {
				fmt.Printf("\r  Model progress: %d/%d chunks classified", done, total)
			}
		})
		fmt.Println()
		for i := range modelFindings {
			modelFindings[i].DetectorSource = "model"
		}
		fmt.Printf("  Model found %d additional secrets\n", len(modelFindings))
		allFindings = append(allFindings, modelFindings...)
	}

	rpt.Findings = dedup(allFindings)

	// Update state with scanned files
	if s.State != nil {
		for _, p := range scannedPaths {
			s.State.MarkScanned(p)
		}
	}

	return rpt, nil
}

// sortByModTimeDesc sorts file paths by modification time, newest first.
func sortByModTimeDesc(files []string) {
	sort.Slice(files, func(i, j int) bool {
		infoI, errI := os.Stat(files[i])
		infoJ, errJ := os.Stat(files[j])
		if errI != nil || errJ != nil {
			return false
		}
		return infoI.ModTime().After(infoJ.ModTime())
	})
}

// trufflehogDirs returns the directories TruffleHog should scan.
func trufflehogDirs() []string {
	home, _ := os.UserHomeDir()
	var dirs []string
	claudeDir := home + "/.claude"
	codexDir := home + "/.codex"
	if info, err := os.Stat(claudeDir); err == nil && info.IsDir() {
		dirs = append(dirs, claudeDir)
	}
	if info, err := os.Stat(codexDir); err == nil && info.IsDir() {
		dirs = append(dirs, codexDir)
	}
	return dirs
}

// shouldSendToModel pre-filters text chunks to decide if they're worth
// sending to the model. Only chunks with suspicious signals are sent.
func shouldSendToModel(text string) bool {
	if len(text) < 20 || len(text) > 10000 {
		return false
	}
	if strings.Contains(text, "=") && (strings.Contains(text, "KEY") ||
		strings.Contains(text, "SECRET") ||
		strings.Contains(text, "TOKEN") ||
		strings.Contains(text, "PASSWORD") ||
		strings.Contains(text, "PASS")) {
		return true
	}
	if strings.Contains(text, "://") && (strings.Contains(text, "@") || strings.Contains(text, "password")) {
		return true
	}
	if strings.Contains(text, "Bearer ") || strings.Contains(text, "Authorization:") {
		return true
	}
	return false
}

// dedup removes duplicate findings based on matched_text + pattern_name.
func dedup(findings []report.Finding) []report.Finding {
	type key struct{ pattern, text string }
	seen := make(map[key]bool)
	var result []report.Finding
	for _, f := range findings {
		k := key{f.PatternName, f.MatchedText}
		if !seen[k] {
			seen[k] = true
			result = append(result, f)
		}
	}
	return result
}
