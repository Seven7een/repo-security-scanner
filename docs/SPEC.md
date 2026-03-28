# SPEC.md — Repo Security Scanner

## Purpose

Automated security scanner that discovers GitHub and GitLab repositories, clones them as bare mirrors, and scans full git history for secrets and PII using gitleaks and AI-powered analysis via Claude (AWS Bedrock).

## Functional Requirements

### Repository Discovery
- Discover public repos via GitHub API (`/users/{username}/repos`)
- Discover private repos when `GITHUB_TOKEN` is provided (`/user/repos`)
- Discover public repos via GitLab API (`/users/{username}/projects`)
- Discover private repos when `GITLAB_TOKEN` is provided (`/projects?membership=true`)
- Support multiple usernames via `GITHUB_USERS` and `GITLAB_USERS` env vars
- Handle API pagination (Link header, X-Next-Page)
- Combined discovery across all providers via `discover_all_repos()`

### Clone Manager
- First run: `git clone --mirror` into `/data/repos/{provider}/{repo}.git`
- Subsequent runs: `git fetch --all --prune` (cache-aware)
- Token injection for private repos (GitHub: `x-access-token`, GitLab: `oauth2`)
- Redacted URL logging (no tokens in logs)

### Gitleaks Scanner
- Run `gitleaks detect` against each mirrored repo (full history)
- Custom config extends defaults with PII rules (email, phone, private IPs)
- Structured findings: repo, tool, rule_id, severity, file, line, commit, snippet

### AI Scanner (Phase 2)
- Extract text content from repo HEAD (candidate file types + commit messages)
- Send to Claude via AWS Bedrock for contextual PII/secret analysis
- Handles markdown code blocks in response, JSON parsing with fallbacks
- Findings tagged with `tool: "ai"` and include category + recommendation
- Graceful error handling — single repo failures don't crash the scan
- Content capped at ~80K characters to fit context window

### Report Generator
- `findings.json` — structured JSON with metadata + findings (includes tool source)
- `report.md` — human-readable Markdown with summary table, per-repo findings, recommendations
- Summary shows findings breakdown by tool (gitleaks vs ai)
- Output to `/output/` (mounted volume)

### Email Reporter (Phase 2)
- Send scan summary via SMTP with STARTTLS after scan completes
- Only sends when `--email` flag is passed AND SMTP env vars are configured
- Includes severity breakdown, tool breakdown, and critical/high findings detail
- Subject line includes date and finding count

### CLI Interface
- `python scan.py [--gitleaks] [--ai] [--all] [--email] [--verbose] [--json-only]`
- `--gitleaks`: run gitleaks only
- `--ai`: run AI scan only
- `--all`: run both gitleaks + AI
- Default (no flags): gitleaks only. AI requires explicit `--ai` or `--all`.
- `--email`: send email report after scan
- Exit codes: 0=clean, 1=findings, 2=error
- Pipeline: discover → clone → scan(gitleaks) → scan(ai) → report → email

## Non-Functional Requirements
- All config via environment variables
- Type hints and docstrings on all public functions
- Logging via Python `logging` module
- Proper error handling for network, git, subprocess, and Bedrock failures
- Token/credential redaction in all log output
- Docker-based deployment
