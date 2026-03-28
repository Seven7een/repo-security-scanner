# CLAUDE.md — Repo Security Scanner

## Forge Conventions

This project was scaffolded following [The Forge](https://github.com/seven7een/the-forge) conventions.

- **Priority order:** Privacy/Security > Functionality > Extensibility > Elegance
- **Never commit:** secrets, API keys, tokens, PII, personal details, .env files
- **Environment variables:** anything that can be an env var must be one. See `.env.example`.
- `.internal/` is gitignored scratch space
- `docs/SPEC.md` — what this project does
- `docs/STATE.md` — what's done and what's blocked (update before every commit)
- `docs/WORKFLOW.md` — how to develop, test, and deploy
- A gitleaks pre-commit hook scans every commit for secrets. Treat findings as hard blockers.

## Project Overview

Standalone Docker container that clones GitHub/GitLab repos and scans for secrets and PII using gitleaks (pattern-based) and Claude via AWS Bedrock (contextual AI analysis). CLI tool — invoke, scan, output, exit.

## Key Conventions

- All subprocess calls must have timeouts and error checking
- Token/credential redaction in ALL log output (`_redact_url()`)
- Logging via Python `logging` module, never `print()`
- Bedrock/gitleaks errors per-repo don't crash the scan — log and continue
- Exit codes: 0=clean, 1=findings, 2=error

## Project Structure

```
scan.py                    # CLI entrypoint (argparse)
lib/
├── discovery.py           # GitHub + GitLab API repo discovery
├── clone_manager.py       # git clone --mirror / fetch
├── gitleaks_scanner.py    # gitleaks wrapper
├── ai_scanner.py          # Bedrock/Claude contextual scanner
├── report.py              # JSON + Markdown reports
└── email_reporter.py      # SMTP email delivery
config/
└── .gitleaks.toml         # Custom PII rules for target repos
```

## Build & Run

```bash
docker build -t repo-security-scanner .
docker run --rm -v ./output:/output -e GITHUB_USERS=myuser repo-security-scanner --all
```
