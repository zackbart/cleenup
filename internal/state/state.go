package state

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// FileState tracks scan/redact status for a single file.
type FileState struct {
	ModTime   time.Time `json:"mod_time"`
	ScannedAt time.Time `json:"scanned_at"`
	Redacted  bool      `json:"redacted"`
}

// State holds the scan history for all tracked files.
type State struct {
	ScannedFiles map[string]FileState `json:"scanned_files"`
	path         string
}

// DefaultPath returns the default state file location (~/.cleenup/state.json).
func DefaultPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".cleenup", "state.json")
}

// Load reads state from disk. Returns empty state if file doesn't exist.
func Load(path string) (*State, error) {
	s := &State{
		ScannedFiles: make(map[string]FileState),
		path:         path,
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		return nil, err
	}

	if err := json.Unmarshal(data, s); err != nil {
		return nil, err
	}
	if s.ScannedFiles == nil {
		s.ScannedFiles = make(map[string]FileState)
	}
	s.path = path
	return s, nil
}

// Save writes state atomically to disk.
func (s *State) Save() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// ShouldScan returns true if the file needs scanning (new or modified since last scan).
func (s *State) ShouldScan(path string) bool {
	fs, ok := s.ScannedFiles[path]
	if !ok {
		return true
	}
	info, err := os.Stat(path)
	if err != nil {
		return true
	}
	return info.ModTime().After(fs.ModTime)
}

// MarkScanned records that a file was successfully scanned.
func (s *State) MarkScanned(path string) {
	info, err := os.Stat(path)
	modTime := time.Now()
	if err == nil {
		modTime = info.ModTime()
	}
	s.ScannedFiles[path] = FileState{
		ModTime:   modTime,
		ScannedAt: time.Now(),
		Redacted:  false,
	}
}

// MarkRedacted records that a file was redacted and updates its mod_time.
func (s *State) MarkRedacted(path string) {
	info, err := os.Stat(path)
	modTime := time.Now()
	if err == nil {
		modTime = info.ModTime()
	}
	fs := s.ScannedFiles[path]
	fs.ModTime = modTime
	fs.Redacted = true
	s.ScannedFiles[path] = fs
}
