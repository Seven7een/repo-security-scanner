# Repo Security Scanner

Docker-based tool that discovers GitHub repositories, clones them, and scans for secrets and PII using [gitleaks](https://github.com/gitleaks/gitleaks).

## Quick Start

```bash
# Build
docker build -t repo-security-scanner .

# Scan public repos
docker run --rm \
  -v ./output:/output \
  -e GITHUB_USERS=your-username \
  repo-security-scanner

# With persistent cache (faster subsequent runs)
docker run --rm \
  -v ./output:/output \
  -v ./cache:/data/repos \
  -e GITHUB_USERS=your-username \
  repo-security-scanner

# Include private repos (requires GitHub PAT)
docker run --rm \
  -v ./output:/output \
  -e GITHUB_USERS=your-username \
  -e GITHUB_TOKEN=ghp_your_token \
  repo-security-scanner

# Verbose mode
docker run --rm \
  -v ./output:/output \
  -e GITHUB_USERS=your-username \
  repo-security-scanner --gitleaks --verbose

# JSON output only
docker run --rm \
  -v ./output:/output \
  -e GITHUB_USERS=your-username \
  repo-security-scanner --json-only
```

## Output

Reports are written to `/output` (mount a volume):

- `findings.json` — structured JSON with scan metadata and all findings
- `report.md` — human-readable Markdown summary

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Clean — no findings |
| 1 | Findings detected |
| 2 | Error during execution |

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `GITHUB_USERS` | Yes | Comma-separated GitHub usernames |
| `GITHUB_TOKEN` | No | GitHub PAT for private repos + higher rate limits |

## Phase 1 (Current)

- GitHub repository discovery (public + private with token)
- Git mirror cloning with caching
- Gitleaks scanning (full history)
- Custom PII rules (email, phone, private IPs)
- JSON + Markdown reports

## Phase 2 (Planned)

- AI-powered scanning via AWS Bedrock/Claude
- GitLab repository discovery
- Email report delivery
- trufflehog integration
