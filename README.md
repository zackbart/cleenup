# cleenup

Scan Claude Code and Codex CLI session logs for leaked secrets and redact them in-place.

## Install

```bash
brew install zackbart/tap/cleenup
```

Optional: install [TruffleHog](https://github.com/trufflesecurity/trufflehog) for verified secret detection (confirms if a key is still live):
```bash
brew install trufflehog
```

## Usage

```bash
# Scan all session logs
cleenup scan

# Scan 10 most recent sessions
cleenup scan -n 10

# Force rescan (ignore state from previous runs)
cleenup scan --force

# Deep scan with local LLM (requires LM Studio)
cleenup scan --deep

# Preview redactions
cleenup redact --dry-run

# Apply redactions and verify nothing survived
cleenup redact --apply --verify
```

## How it works

cleenup parses JSONL session logs from `~/.claude` and `~/.codex`, extracting text from messages, tool calls, tool results, and bash output. It runs three detection layers:

| Layer | Engine | What it catches |
|-------|--------|-----------------|
| 1 | TruffleHog + built-in regex (40+ patterns) | API keys, tokens, connection strings, private keys, JWTs, env var assignments |
| 2 | Shannon entropy analysis | High-entropy strings that don't match known patterns |
| 3 | Local LLM via [LM Studio](https://lmstudio.ai) | AI classification of suspicious chunks (optional `--deep`) |

Secrets are replaced with `REDACTED_BY_CLEENUP` directly in the JSONL files. Both raw and JSON-escaped forms are replaced. Files are written atomically (temp file + rename).

State is tracked in `~/.cleenup/state.json` so repeat runs skip unchanged files.

## Flags

| Command | Flag | Description |
|---------|------|-------------|
| `scan` | `-n, --limit N` | Scan only the N most recent sessions (0 = all) |
| `scan` | `--force` | Ignore state, rescan everything |
| `scan` | `--deep` | Enable LM Studio classification |
| `scan` | `--port PORT` | LM Studio port (default: 1234) |
| `scan` | `--model NAME` | LM Studio model (auto-detects if empty) |
| `scan` | `-o, --output FILE` | Report output path |
| `redact` | `--dry-run` | Preview redactions (default) |
| `redact` | `--apply` | Redact secrets in-place |
| `redact` | `--verify` | Re-scan after redaction to confirm completeness |
| `redact` | `--report FILE` | Path to scan report |
