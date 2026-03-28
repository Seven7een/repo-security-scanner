# Architecture — Repo Security Scanner

## Overview

Standalone Docker container that scans GitHub and GitLab repositories for secrets and PII. Combines regex-based scanning (gitleaks) with contextual AI analysis (Claude via AWS Bedrock). CLI tool — invoke, scan, output results, exit.

```
docker run --rm \
  -v ./output:/output \
  -v ./cache:/data/repos \
  -e GITHUB_USERS=username \
  repo-security-scanner --gitleaks

┌──────────────────────────────────────────────────────────┐
│  Container: repo-security-scanner                        │
│                                                          │
│  scan.py (entrypoint)                                    │
│  │                                                       │
│  │  Step 1: Discover repos                               │
│  │  ├── GitHub API (/users/{user}/repos)                 │
│  │  └── GitLab API (/users/{user}/projects)              │
│  │                                                       │
│  │  Step 2: Clone / update                               │
│  │  └── git clone --mirror → /data/repos/                │
│  │                                                       │
│  │  Step 3: Gitleaks scan (if --gitleaks or --all)       │
│  │  └── gitleaks detect (full history)                   │
│  │                                                       │
│  │  Step 4: AI scan (if --ai or --all)                   │
│  │  └── Extract content → Bedrock/Claude                 │
│  │                                                       │
│  │  Step 5: Generate reports                             │
│  │  ├── /output/findings.json                            │
│  │  └── /output/report.md                                │
│  │                                                       │
│  │  Step 6: Email (if --email)                           │
│  │  └── SMTP + STARTTLS                                  │
│  │                                                       │
│  └── Exit (0=clean, 1=findings, 2=error)                 │
│                                                          │
│  Volumes:                                                │
│    /output  ← mounted from host (reports)                │
│    /data/repos ← optional cache (cloned repos)           │
└──────────────────────────────────────────────────────────┘
```

---

## Full Pipeline

```
CLI Invocation
  │
  │  docker run repo-security-scanner [--gitleaks] [--ai] [--all] [--email] [--verbose]
  │
  ▼
┌────────────────────────────────┐
│  parse_args()                  │
│  _determine_scanners(args)     │
│                                │
│  Flag logic:                   │
│    --gitleaks     → gitleaks only
│    --ai           → AI only    │
│    --all          → both       │
│    (no flags)     → gitleaks only (default)
│    --email        → send report via SMTP
│    --verbose      → DEBUG logging
│    --json-only    → skip markdown report
└────────┬───────────────────────┘
         │
         ▼
Step 1: DISCOVER REPOS
  │
  │  discover_all_repos()
  │  ├── discover_all_github_repos()
  │  │     Reads GITHUB_USERS (comma-separated)
  │  │     For each username → discover_github_repos(username)
  │  │     Returns list of repo dicts
  │  │
  │  └── discover_all_gitlab_repos()  (optional)
  │        Reads GITLAB_USERS (comma-separated)
  │        If not set → skip silently
  │        For each username → discover_gitlab_repos(username)
  │
  │  Output: list of repo dicts with:
  │    {name, full_name, clone_url, private, provider, default_branch}
  │
  ▼
Step 2: CLONE / UPDATE REPOS
  │
  │  clone_or_update_repos(repos)
  │  For each repo:
  │    path = /data/repos/{provider}/{name}.git
  │    If path exists:
  │      git fetch --all --prune (incremental)
  │    Else:
  │      git clone --mirror {clone_url} {path}
  │
  │  Adds 'local_path' key to each repo dict
  │
  ▼
Step 3: GITLEAKS SCAN (if selected)
  │
  │  scan_all_repos(repos)
  │  For each repo:
  │    gitleaks detect --source {path} --report-format json
  │    Parse JSON findings → structured dicts
  │  Returns: list of finding dicts
  │
  ▼
Step 4: AI SCAN (if selected)
  │
  │  scan_all_repos_with_ai(repos)
  │  For each repo (sequential — respects rate limits):
  │    Extract text content from HEAD
  │    Send to Claude via Bedrock
  │    Parse JSON response
  │  Returns: list of finding dicts
  │
  ▼
Step 5: GENERATE REPORTS
  │
  │  generate_reports(findings, repos)
  │  → /output/findings.json (structured JSON)
  │  → /output/report.md (markdown summary)
  │
  ▼
Step 6: EMAIL (if --email)
  │
  │  send_email_report(findings, repos, markdown)
  │  → SMTP with STARTTLS to ALERT_EMAIL
  │
  ▼
EXIT
  code 0: no findings
  code 1: findings detected
  code 2: error
```

---

## GitHub Discovery

### Public Repos (no token)

```
GET https://api.github.com/users/{username}/repos?type=public&per_page=100

Rate limit: 60 requests/hour (by IP)
```

### Private + Public Repos (with token)

```
GET https://api.github.com/user/repos?visibility=all&per_page=100
Authorization: Bearer {GITHUB_TOKEN}

Rate limit: 5000 requests/hour
```

When using a token, the `/user/repos` endpoint returns **all repos the token can access** (including org repos). The code filters results by `owner.login` to match only the requested username.

### Pagination

GitHub returns a `Link` header with `rel="next"` for paginated results. The discovery module follows these links until no more pages exist.

```python
while url:
    response = session.get(url)
    repos.extend(response.json())
    url = _get_next_url(response.headers.get("Link", ""))
```

### Repo Dict Structure

```python
{
    "name": "repo-name",
    "full_name": "github/username/repo-name",  # provider/owner/name
    "clone_url": "https://github.com/username/repo-name.git",
    "private": False,
    "provider": "github",
    "default_branch": "main",
}
```

---

## GitLab Discovery

### Public Repos (no token)

```
GET https://gitlab.com/api/v4/users/{username}/projects?visibility=public&per_page=100
```

### Private + Public Repos (with token)

```
GET https://gitlab.com/api/v4/projects?membership=true&per_page=100
PRIVATE-TOKEN: {GITLAB_TOKEN}
```

Filtered by owner username, same as GitHub.

### Pagination

GitLab uses `X-Next-Page` header (or `Link` header). The code checks both:

```python
next_page = response.headers.get("X-Next-Page", "")
if next_page:
    url = f"{base_url}&page={next_page}"
```

### Optional

GitLab discovery is skipped entirely if `GITLAB_USERS` is not set. No error, just a debug log:

```
GITLAB_USERS not set, skipping GitLab discovery
```

---

## Clone Manager

### First Run (fresh clone)

```bash
git clone --mirror https://github.com/user/repo.git /data/repos/github/repo.git
```

`--mirror` creates a bare repository with:
- Full commit history (all branches, all tags)
- All refs
- No working tree (saves disk space)

This is essential for scanning git history — gitleaks needs access to all commits.

### Subsequent Runs (incremental update)

```bash
cd /data/repos/github/repo.git
git fetch --all --prune
```

Only downloads new commits since last fetch. `--prune` removes refs that no longer exist on remote.

### Cache Volume

The `/data/repos` directory can be mounted as a Docker volume for persistence between runs:

```bash
# With cache (fast after first run)
docker run -v ./cache:/data/repos ...

# Without cache (clones everything fresh each time)
docker run ...
```

### Token Injection

For private repos, tokens are injected into the clone URL at runtime:

```python
# GitHub
clone_url = "https://x-access-token:{token}@github.com/user/repo.git"

# GitLab
clone_url = "https://oauth2:{token}@gitlab.com/user/repo.git"
```

### Token Redaction

All URLs are redacted before logging:

```python
def _redact_url(url: str) -> str:
    # "https://x-access-token:ghp_abc123@github.com/..."
    # → "https://[REDACTED]@github.com/..."
```

Tokens **never** appear in log output.

---

## Gitleaks Scanner

### Invocation

For each repo:

```bash
gitleaks detect \
  --source /data/repos/github/repo.git \
  --report-format json \
  --report-path /tmp/gitleaks-{repo-name}.json \
  --config /app/config/.gitleaks.toml \
  --no-banner
```

This scans **full git history** (all commits, all branches) — not just HEAD.

### Custom Rules (`config/.gitleaks.toml`)

Extends the default gitleaks ruleset with PII-specific patterns:

```toml
[extend]
# Inherits all ~70 default rules (AWS keys, generic tokens, etc.)

[[rules]]
id = "pii-email"
description = "Email address in code"
regex = '''[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'''
tags = ["pii", "email"]

[[rules]]
id = "pii-phone"
description = "Phone number"
regex = '''\+?[0-9]{1,4}[-.\s]?\(?[0-9]{1,3}\)?[-.\s]?[0-9]{3,4}[-.\s]?[0-9]{3,4}'''
tags = ["pii", "phone"]

[[rules]]
id = "private-ip"
description = "Private/internal IP address"
regex = '''(?:10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|192\.168\.)\d{1,3}\.\d{1,3}'''
tags = ["infrastructure"]

[extend.allowlist]
paths = ['''\.gitleaks\.toml$''', '''\.env\.example$''']
```

### Severity Classification

The gitleaks wrapper maps known rule IDs to severity levels:

```
critical: generic-api-key, private-key
high:     aws-secret-key, gcp-api-key, slack-token, stripe-api-key
medium:   (default for unknown rules)
low:      pii-email, pii-phone, private-ip
```

### Finding Structure

Each gitleaks finding is normalized to:

```python
{
    "repo": "github/username/repo-name",
    "tool": "gitleaks",
    "rule_id": "pii-email",
    "description": "Email address in code",
    "severity": "low",
    "category": "pii",          # derived from tags
    "file": "src/config.py",
    "line": 42,
    "commit": "abc123def456",
    "snippet": "user@example.com",  # truncated to 200 chars
    "author": "Author Name",
    "date": "2026-01-15",
    "tags": ["pii", "email"],
}
```

### Exit Code Handling

Gitleaks exits with code 1 when findings are detected. The wrapper treats this as success (findings found), not an error. Only unexpected exit codes (>1) are treated as errors.

---

## AI Scanner

### Purpose

Catches what regex can't — contextual PII, personal details in comments and documentation, names of family members, home addresses, sensitive relationships described in READMEs, etc.

### Content Extraction

```
scan_repo_with_ai(repo)
  │
  │  Step 1: Checkout HEAD to temp directory
  │
  │  Primary method: git worktree add
  │    git -C /data/repos/github/repo.git worktree add --detach /tmp/ai-scan-xxx HEAD
  │
  │  Fallback (if worktree fails on bare repos):
  │    git archive --format=tar HEAD | tar -x -C /tmp/ai-scan-xxx
  │
  │  Step 2: Collect candidate files
  │    Extensions: .md .txt .yml .yaml .json .toml .cfg .ini
  │                .sh .py .js .rb .go .ts
  │    Also: any file starting with .env
  │    Skip: files > 100KB, binary files, .git directory
  │
  │  Step 3: Extract commit messages
  │    git log --max-count=50 --format="%H %an <%ae> %s"
  │
  │  Step 4: Concatenate with file headers
  │    --- FILE: src/config.py ---
  │    <file content>
  │
  │    --- FILE: README.md ---
  │    <file content>
  │
  │    --- RECENT COMMIT MESSAGES (last 50) ---
  │    <commit messages>
  │
  │  Step 5: Cap at 80,000 characters (~20K tokens)
  │
  │  Step 6: Clean up worktree
  │    git worktree remove --force /tmp/ai-scan-xxx
  │
  ▼
  Content string ready for Claude
```

### Bedrock Integration

```python
client = boto3.client("bedrock-runtime", region_name=AWS_REGION)

body = {
    "anthropic_version": "bedrock-2023-05-31",
    "max_tokens": 8192,
    "messages": [{
        "role": "user",
        "content": f"{CLAUDE_PROMPT}\n\n--- REPOSITORY CONTENT ---\n{content}"
    }],
    "temperature": 0.0,  # deterministic for consistent results
}

response = client.invoke_model(
    modelId=BEDROCK_MODEL_ID,
    contentType="application/json",
    accept="application/json",
    body=json.dumps(body),
)
```

**Model:** `BEDROCK_MODEL_ID` env var (default: `us.anthropic.claude-sonnet-4-20250514`)
**Region:** `AWS_REGION` env var (default: `us-east-1`)
**Auth:** `AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY` env vars

### Claude Prompt

```
You are a security auditor specializing in PII and secret detection
in source code repositories.

Analyze the following repository content and identify:
1. PII: real names, email addresses, phone numbers, physical addresses,
   account IDs, usernames tied to real people
2. Hardcoded secrets: API keys, passwords, tokens, connection strings
   that appear to be real (not placeholders)
3. Infrastructure details: internal IPs, hostnames, network topology
   that shouldn't be public
4. Sensitive context: comments or documentation revealing personal
   relationships, habits, home locations

For each finding, respond with this JSON structure:
{
  "findings": [
    {
      "severity": "critical|high|medium|low",
      "category": "pii|secret|infrastructure|context",
      "file": "path/to/file",
      "line": 42,
      "snippet": "the relevant text",
      "description": "what was found and why it's a risk",
      "recommendation": "how to fix it"
    }
  ]
}

If no findings, return: {"findings": []}

Only report genuine issues — ignore placeholder values, example configs,
and test data that is clearly not real.
```

### JSON Response Parsing

Claude sometimes wraps JSON in markdown code blocks. The parser handles this:

```python
text = response_text.strip()
if text.startswith("```"):
    # Strip ```json ... ```
    first_newline = text.index("\n")
    text = text[first_newline + 1:]
    if text.endswith("```"):
        text = text[:-3]
```

Also handles cases where Claude includes explanatory text around the JSON — finds the first `{` and last `}` to extract the object.

### Rate Limiting

Repos are processed **sequentially** (not concurrently) to respect Bedrock rate limits. Estimated cost: ~$0.01-0.05 per repo depending on content size.

### Error Handling

Per-repo errors are caught and logged. The scan continues with remaining repos:

```python
for repo in repos:
    try:
        findings = scan_repo_with_ai(repo)
    except Exception as e:
        logger.error("AI scan failed for '%s': %s", repo["full_name"], e)
        continue  # don't crash, scan next repo
```

### AI Finding Structure

```python
{
    "repo": "github/username/repo-name",
    "tool": "ai",
    "rule_id": "ai-pii",           # "ai-" + category
    "description": "Real name found in README comment",
    "severity": "medium",
    "category": "pii",
    "file": "README.md",
    "line": 15,
    "commit": "",                   # AI doesn't scan history, just HEAD
    "snippet": "Built by John Doe",
    "recommendation": "Remove personal name, use a pseudonym or org name",
    "author": "",
    "date": "",
    "tags": ["pii"],
}
```

---

## Report Generator

### JSON Report (`/output/findings.json`)

```json
{
    "scan_id": "uuid",
    "timestamp": "2026-03-22T16:32:35.089940+00:00",
    "duration_seconds": 7.8,
    "repos_scanned": 11,
    "repos_with_findings": 6,
    "total_findings": 523,
    "severity_counts": {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 523
    },
    "tool_counts": {
        "gitleaks": 523
    },
    "findings": [
        {
            "repo": "github/Seven7een/museick",
            "tool": "gitleaks",
            "rule_id": "pii-email",
            "severity": "low",
            "file": "src/App.js",
            "line": 42,
            "commit": "abc123",
            "snippet": "user@example.com",
            "description": "Email address in code",
            ...
        }
    ]
}
```

### Markdown Report (`/output/report.md`)

```markdown
# 🔍 Repository Security Scan Report

**Scan Time:** 2026-03-22T16:32:35+00:00
**Scanners:** gitleaks

## Summary
| Metric              | Value |
|---------------------|-------|
| Repositories Scanned | 11   |
| Repos with Findings  | 6    |
| Total Findings       | 523  |
| 🔎 Findings (gitleaks) | 523 |
| 🔵 Low              | 523  |

## Findings by Repository

### Seven7een/museick
**356 finding(s)**

1. 🔵 [LOW] [gitleaks] pii-email
   - File: src/App.js:42
   - Commit: abc123
   - Match: user@example.com
...

## Recommendations
...
```

When both tools are active (`--all`), the report includes separate counts:

```
| 🔎 Findings (gitleaks) | 523 |
| 🤖 Findings (ai)       | 12  |
```

---

## Email Reporter

### Configuration

| Variable | Default | Description |
|---|---|---|
| `SMTP_HOST` | smtp.gmail.com | SMTP server |
| `SMTP_PORT` | 587 | SMTP port |
| `SMTP_USER` | — | Login username |
| `SMTP_PASS` | — | Login password |
| `ALERT_EMAIL` | — | Recipient address |

All three of `SMTP_USER`, `SMTP_PASS`, and `ALERT_EMAIL` must be set. If any are missing, email is skipped with a warning.

### Email Content

```
Subject: Security Scan Report — 2026-03-22 — 523 findings

Body:
  - Scan date and stats
  - Severity breakdown (critical/high/medium/low)
  - Tool breakdown (gitleaks/ai)
  - Top critical/high findings (first 20)
  - Full markdown report attached as second MIME part
```

### Delivery

```python
with smtplib.SMTP(smtp_host, smtp_port, timeout=30) as server:
    server.ehlo()
    server.starttls()
    server.ehlo()
    server.login(smtp_user, smtp_pass)
    server.sendmail(smtp_user, [alert_email], msg.as_string())
```

### Error Handling

Email is **best-effort**. Failures are logged but never raise:

```python
try:
    server.sendmail(...)
    return True
except Exception as e:
    logger.error("Failed to send email report: %s", e)
    return False
```

---

## Docker

### Image

```dockerfile
FROM python:3.12-slim-bookworm

# Install git + gitleaks (latest release from GitHub)
RUN apt-get install git ca-certificates curl \
    && curl gitleaks tarball → /usr/local/bin/gitleaks

COPY requirements.txt → pip install
COPY . → /app

ENTRYPOINT ["python", "scan.py"]
CMD ["--all"]
```

**Image size:** ~266MB

### Volume Mounts

| Host Path | Container Path | Purpose | Required |
|---|---|---|---|
| `./output` | `/output` | Report output (JSON + Markdown) | Yes |
| `./cache` | `/data/repos` | Cloned repo cache | No (optional, speeds up repeat runs) |

### Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `GITHUB_USERS` | Yes* | — | Comma-separated GitHub usernames |
| `GITLAB_USERS` | No | — | Comma-separated GitLab usernames |
| `GITHUB_TOKEN` | No | — | GitHub PAT (private repos + 5000 req/hr) |
| `GITLAB_TOKEN` | No | — | GitLab PAT (private repos) |
| `AWS_ACCESS_KEY_ID` | For --ai | — | Bedrock auth |
| `AWS_SECRET_ACCESS_KEY` | For --ai | — | Bedrock auth |
| `AWS_REGION` | No | us-east-1 | Bedrock region |
| `BEDROCK_MODEL_ID` | No | us.anthropic.claude-sonnet-4-20250514 | Claude model |
| `SMTP_HOST` | For --email | smtp.gmail.com | SMTP server |
| `SMTP_PORT` | For --email | 587 | SMTP port |
| `SMTP_USER` | For --email | — | SMTP login |
| `SMTP_PASS` | For --email | — | SMTP password |
| `ALERT_EMAIL` | For --email | — | Report recipient |

*At least one of `GITHUB_USERS` or `GITLAB_USERS` is required.

---

## CLI Reference

### Flags

| Flag | Description | Default |
|---|---|---|
| `--gitleaks` | Run gitleaks scan only | ✅ (default when no flags) |
| `--ai` | Run AI scan only | |
| `--all` | Run both gitleaks + AI | |
| `--email` | Send email report | Off |
| `--verbose` | DEBUG-level logging | INFO |
| `--json-only` | Skip markdown report | Both formats |

### Exit Codes

| Code | Meaning |
|---|---|
| `0` | Scan completed, no findings |
| `1` | Scan completed, findings detected |
| `2` | Error during execution (discovery/clone/scan/report failed) |

### Usage Examples

```bash
# Basic: scan public repos with gitleaks
docker run --rm -v ./output:/output -e GITHUB_USERS=myuser repo-security-scanner

# Full scan with AI
docker run --rm -v ./output:/output \
  -e GITHUB_USERS=myuser \
  -e AWS_ACCESS_KEY_ID=... -e AWS_SECRET_ACCESS_KEY=... \
  repo-security-scanner --all

# With cache + email
docker run --rm -v ./output:/output -v ./cache:/data/repos \
  --env-file .env \
  repo-security-scanner --all --email

# Weekly cron
0 3 * * 0 docker run --rm -v /path/output:/output --env-file /path/.env \
  repo-security-scanner --all --email
```
