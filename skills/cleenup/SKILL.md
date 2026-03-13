---
name: cleenup
description: >
  Scan and redact leaked secrets from Claude Code and Codex CLI session logs.
  Invoked explicitly by the user (e.g., /cleenup) or via a hook. Runs the cleenup
  CLI to find API keys, tokens, passwords, and credentials in ~/.claude and ~/.codex
  session logs, then guides the user through reviewing and redacting findings.
user_invocable: true
---

# cleenup — Session Log Secret Scanner

Scan Claude Code and Codex CLI session logs for leaked secrets and redact them in-place.

## Pre-flight

Check if `cleenup` is installed:

```bash
which cleenup
```

If not found, install it:

```bash
brew install zackbart/tap/cleenup
```

Also check if TruffleHog is available — optional but adds verified detection (confirms if a key is still live):

```bash
which trufflehog
```

If missing, mention it can be installed with `brew install trufflehog` but isn't required.

## Workflow

Run through these stages in order. Let the tool output speak for itself.

### 1. Scan

```bash
cleenup scan
```

Forward any arguments the user passed (e.g., `/cleenup -n 10 --force` becomes `cleenup scan -n 10 --force`).

Flags:
- `-n N` — scan only the N most recent sessions
- `--force` — ignore state, rescan everything
- `--deep` — enable local LLM classification (requires LM Studio running)
- `--model NAME` — specify LM Studio model (auto-detects if empty)

### 2. Review

If secrets were found:
- Report count and affected files
- Call out verified-live secrets (marked `[VERIFIED]`) as highest priority
- Distinguish real credentials from lower-risk findings (placeholder values, high-entropy strings)

If clean, say so and stop.

### 3. Redact

If secrets were found, ask the user if they want to redact. If yes:

```bash
cleenup redact --apply --verify
```

This replaces secrets with `REDACTED_BY_CLEENUP` in the JSONL files and re-scans to confirm nothing survived. The report at `~/.cleenup/report.json` has full details of what was found.

### 4. Summary

Report: files scanned, secrets found by category, redactions applied, verification result.

## Argument handling

- `/cleenup` — full scan with defaults
- `/cleenup -n 5` — scan 5 most recent sessions
- `/cleenup --force` — rescan everything
- `/cleenup --deep` — include LM Studio classification
- `/cleenup redact` — skip scan, go straight to redact using existing report
