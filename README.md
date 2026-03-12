# cleenup

Scan Claude Code and Codex CLI session logs for leaked secrets. Finds API keys, tokens, passwords, connection strings, and other credentials that may have been inadvertently captured in `~/.claude` and `~/.codex` session logs.

## How it works

cleenup uses a layered detection pipeline:

| Layer | Engine | What it catches |
|-------|--------|-----------------|
| 1 | [TruffleHog](https://github.com/trufflesecurity/trufflehog) | Known secret formats with optional verification (confirms if a key is still live) |
| 1 | Built-in regex (40+ patterns) | API keys, tokens, env var assignments, connection strings, private keys, JWTs |
| 2 | Shannon entropy analysis | High-entropy strings that don't match known patterns but look like secrets |
| 3 | Local LLM via [LM Studio](https://lmstudio.ai) | AI-powered classification of suspicious text chunks (optional `--deep` mode) |

All layers run on parsed text extracted from JSONL session logs. The JSONL parsers understand Claude and Codex log formats and extract text from messages, tool calls, tool results, bash output, and more.

## Install

```bash
go install ./cmd/cleenup/
```

Optional (recommended): install TruffleHog for verified secret detection:
```bash
brew install trufflehog
```

## Usage

### Scan for secrets

```bash
# Scan all session logs
cleenup scan

# Scan the 10 most recent sessions
cleenup scan -n 10

# Force rescan (ignore state from previous runs)
cleenup scan --force

# Deep scan with local LLM (requires LM Studio running)
cleenup scan --deep --model qwen3.5-2b

# Save report to a custom path
cleenup scan -o ~/report.json
```

### Redact secrets

```bash
# Preview what would be redacted
cleenup redact --dry-run

# Apply redactions in-place
cleenup redact --apply

# Apply and verify no secrets survived
cleenup redact --apply --verify
```

### Flags

| Command | Flag | Description |
|---------|------|-------------|
| `scan` | `-n, --limit N` | Scan only the N most recent sessions (0 = all) |
| `scan` | `--force` | Ignore state, rescan everything |
| `scan` | `--deep` | Enable LM Studio classification layer |
| `scan` | `--port PORT` | LM Studio API port (default: 1234) |
| `scan` | `--model NAME` | LM Studio model (auto-detects if empty) |
| `scan` | `-o, --output FILE` | Report output path |
| `redact` | `--dry-run` | Preview redactions without modifying files (default) |
| `redact` | `--apply` | Actually redact secrets in-place |
| `redact` | `--verify` | Re-scan after redaction to confirm completeness |
| `redact` | `--report FILE` | Path to scan report |

## What it scans

- **Claude Code**: `~/.claude/projects/**/*.jsonl`, `~/.claude/history.jsonl`
- **Codex CLI**: `~/.codex/sessions/**/*.jsonl`, `~/.codex/history.jsonl`

Extracted content includes:
- User and assistant messages
- Tool use commands (bash, write, edit)
- Tool results and output
- Bash progress output
- Agent and subagent messages
- Function call arguments and outputs
- Queue operations

## State tracking

cleenup tracks scan history in `~/.cleenup/state.json` to avoid re-scanning unchanged files on repeat runs. Use `--force` to override.

## Detection details

### Built-in patterns (40+)

AWS, Anthropic, OpenAI, GitHub, GitLab, Stripe, Slack, SendGrid, Square, npm, PyPI, Notion, Hugging Face, Google, DigitalOcean, Tailscale, Vercel, Supabase, Netlify, Twilio, Postman, Sentry, Firebase, WorkOS, age encryption keys, private keys, certificates, JWTs, connection strings (PostgreSQL, MySQL, MongoDB, Redis, AMQP, MSSQL, and more).

### Environment variable detection

Detects sensitive environment variable assignments (`export SECRET_KEY=value`) using a curated list of 50+ known sensitive variable names and 12 sensitive substrings (SECRET, TOKEN, PASSWORD, KEY, DSN, WEBHOOK, etc.).

### Entropy analysis

Tokens 30+ characters with Shannon entropy above 5.0 bits are flagged. Extensive false-positive filtering excludes UUIDs, git SHAs, known internal IDs (Claude tool IDs, API request IDs), file paths, and previously redacted markers.

### LM Studio deep scan

When `--deep` is enabled, suspicious text chunks are sent to a local LLM for classification. Supports thinking models (Qwen 3.5, etc.) with automatic `<think>` tag stripping. Tested at 100% accuracy with qwen3.5-2b.

## Redaction

Redaction replaces secrets with `[REDACTED:PatternName]` markers directly in the JSONL files. Both raw and JSON-escaped forms of secrets are replaced to handle special characters. Files are written atomically (temp file + rename) to prevent corruption.

Use `--verify` to re-scan after redaction and confirm no secrets survived.

## Project structure

```
cmd/cleenup/main.go          CLI entry point (Cobra)
internal/scanner/
  scanner.go                  Orchestrator with parallel worker pool
  patterns.go                 40+ compiled regex patterns
  detector.go                 Regex + env var assignment detection
  entropy.go                  Shannon entropy analysis
  trufflehog.go               TruffleHog integration
  claude.go                   Claude JSONL parser
  codex.go                    Codex JSONL parser
internal/model/lmstudio.go   LM Studio client for deep scanning
internal/redactor/redactor.go Atomic redaction engine
internal/report/report.go    Finding types, JSON serialization, summary
internal/state/state.go      Incremental scan state tracking
```
