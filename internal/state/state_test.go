package state

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestStateLoadSave(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	// Load non-existent file — should return empty state
	st, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(st.ScannedFiles) != 0 {
		t.Errorf("expected empty state, got %d entries", len(st.ScannedFiles))
	}

	// Mark a file as scanned
	tmpFile := filepath.Join(dir, "test.jsonl")
	if err := os.WriteFile(tmpFile, []byte("test"), 0o644); err != nil {
		t.Fatal(err)
	}
	st.MarkScanned(tmpFile)

	// Save and reload
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}

	st2, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(st2.ScannedFiles) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(st2.ScannedFiles))
	}

	fs := st2.ScannedFiles[tmpFile]
	if fs.Redacted {
		t.Error("expected redacted=false")
	}
	if fs.ScannedAt.IsZero() {
		t.Error("expected non-zero scanned_at")
	}
}

func TestShouldScan(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	tmpFile := filepath.Join(dir, "test.jsonl")
	if err := os.WriteFile(tmpFile, []byte("test"), 0o644); err != nil {
		t.Fatal(err)
	}

	st, _ := Load(path)

	// New file — should scan
	if !st.ShouldScan(tmpFile) {
		t.Error("new file should require scanning")
	}

	// Mark scanned
	st.MarkScanned(tmpFile)

	// Unchanged file — should skip
	if st.ShouldScan(tmpFile) {
		t.Error("unchanged file should be skipped")
	}

	// Modify file — should scan again
	time.Sleep(10 * time.Millisecond)
	if err := os.WriteFile(tmpFile, []byte("modified"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !st.ShouldScan(tmpFile) {
		t.Error("modified file should require scanning")
	}
}

func TestMarkRedacted(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	tmpFile := filepath.Join(dir, "test.jsonl")
	if err := os.WriteFile(tmpFile, []byte("test"), 0o644); err != nil {
		t.Fatal(err)
	}

	st, _ := Load(path)
	st.MarkScanned(tmpFile)
	st.MarkRedacted(tmpFile)

	fs := st.ScannedFiles[tmpFile]
	if !fs.Redacted {
		t.Error("expected redacted=true after MarkRedacted")
	}
}
