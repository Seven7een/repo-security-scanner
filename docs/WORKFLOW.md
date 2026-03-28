# WORKFLOW.md — Repo Security Scanner

## Development

### Prerequisites
- Docker
- (Optional) Python 3.12+ for local development

### Build
```bash
docker build -t repo-security-scanner .
```

### Run
```bash
# Basic scan
docker run --rm \
  -v ./output:/output \
  -e GITHUB_USERS=username \
  repo-security-scanner

# With cache volume
docker run --rm \
  -v ./output:/output \
  -v ./cache:/data/repos \
  -e GITHUB_USERS=username \
  repo-security-scanner

# Verbose
docker run --rm \
  -v ./output:/output \
  -e GITHUB_USERS=username \
  repo-security-scanner --verbose

# JSON only
docker run --rm \
  -v ./output:/output \
  -e GITHUB_USERS=username \
  repo-security-scanner --json-only
```

### Local Development (without Docker)
```bash
pip install -r requirements.txt
# Requires gitleaks installed locally
GITHUB_USERS=username python scan.py --verbose
```

## Testing

Manual testing against public repos:
```bash
docker run --rm \
  -v ./output:/output \
  -e GITHUB_USERS=octocat \
  repo-security-scanner --verbose
```

Check output in `./output/findings.json` and `./output/report.md`.

## Git Conventions
- Short imperative commit messages
- Update `docs/STATE.md` before every commit
- Never commit secrets, tokens, or `.env` files
