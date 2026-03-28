# STATE.md — Repo Security Scanner

## Current Phase: 2 (AI + GitLab + Email)

### ✅ Phase 1 — Complete
- [x] Project structure and Forge conventions
- [x] CLI entrypoint (`scan.py`) with argparse
- [x] GitHub repo discovery with pagination and token support
- [x] Git mirror clone manager with caching
- [x] Gitleaks scanner wrapper with JSON parsing
- [x] Custom gitleaks config with PII rules
- [x] JSON + Markdown report generator
- [x] Dockerfile with gitleaks installation
- [x] Documentation (README, SPEC, WORKFLOW, CLAUDE.md)

### ✅ Phase 2 — Complete
- [x] AI scanning via AWS Bedrock/Claude (`lib/ai_scanner.py`)
  - Content extraction from repo HEAD (text files + commit messages)
  - Claude prompt for PII, secrets, infrastructure, and context analysis
  - JSON response parsing with markdown code block handling
  - Graceful error handling per repo
- [x] GitLab repo discovery (`lib/discovery.py`)
  - Public and private repo discovery
  - Pagination support (X-Next-Page + Link header)
  - Combined `discover_all_repos()` function
- [x] GitLab clone support (`lib/clone_manager.py`)
  - OAuth2 token injection for GitLab URLs
- [x] Email report delivery (`lib/email_reporter.py`)
  - SMTP with STARTTLS
  - Severity and tool breakdowns
  - Full markdown report inclusion
- [x] CLI updates — `--ai`, `--gitleaks`, `--all`, `--email` flags
- [x] Report updates — tool source in findings, AI findings section
- [x] Updated requirements.txt (added boto3)
- [x] Updated .env.example with all Phase 2 env vars
- [x] Updated SPEC.md and STATE.md

### 🔲 Phase 3 (Not Started)
- [ ] Trace + Scrub pipeline (`git log -S` to find first commit, `git filter-repo` to rewrite)
- [ ] Finding diff tracking across runs
- [ ] Local repo path scanning (currently only remote discovery)
- [ ] Test suite

### 🚫 Blocked
- Nothing currently blocked
