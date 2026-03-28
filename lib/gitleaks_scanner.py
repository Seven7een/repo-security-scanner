"""Gitleaks scanner wrapper — runs gitleaks detect and parses results."""

import json
import logging
import subprocess
import tempfile
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

GITLEAKS_CONFIG = "/app/config/.gitleaks.toml"


def scan_repo(repo: dict[str, Any], config_path: str = GITLEAKS_CONFIG, full_matches: bool = False) -> list[dict[str, Any]]:
    """Run gitleaks detect against a single mirrored repo.

    Scans full git history for secrets and PII.

    Args:
        repo: Repo dict with 'local_path', 'name', 'full_name' keys.
        config_path: Path to custom gitleaks TOML config.

    Returns:
        List of finding dicts with structured fields.
    """
    local_path = repo["local_path"]
    logger.info("Scanning %s with gitleaks", repo["full_name"])

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as tmp:
        report_path = tmp.name

    try:
        cmd = [
            "gitleaks", "detect",
            "--source", local_path,
            "--report-format", "json",
            "--report-path", report_path,
            "--no-banner",
        ]

        # Use custom config if it exists
        if Path(config_path).exists():
            cmd.extend(["--config", config_path])

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600,
        )

        # Exit code 0 = no leaks, 1 = leaks found, other = error
        if result.returncode not in (0, 1):
            logger.error(
                "Gitleaks error for '%s': %s",
                repo["full_name"],
                result.stderr.strip(),
            )
            raise RuntimeError(
                f"Gitleaks failed for {repo['full_name']}: {result.stderr.strip()}"
            )

        findings = _parse_report(report_path, repo, full_matches=full_matches)
        logger.info(
            "Found %d findings in %s",
            len(findings),
            repo["full_name"],
        )
        return findings

    finally:
        Path(report_path).unlink(missing_ok=True)


def scan_all_repos(repos: list[dict[str, Any]], config_path: str = GITLEAKS_CONFIG, full_matches: bool = False) -> list[dict[str, Any]]:
    """Scan all repos and return combined findings.

    Args:
        repos: List of repo dicts with 'local_path' key.
        config_path: Path to custom gitleaks TOML config.
        full_matches: If True, don't truncate match snippets.

    Returns:
        Combined list of all findings across repos.
    """
    all_findings: list[dict[str, Any]] = []
    for repo in repos:
        try:
            findings = scan_repo(repo, config_path, full_matches=full_matches)
            all_findings.extend(findings)
        except RuntimeError as e:
            logger.error("Skipping repo due to scan error: %s", e)
    return all_findings


def _parse_report(report_path: str, repo: dict[str, Any], full_matches: bool = False) -> list[dict[str, Any]]:
    """Parse gitleaks JSON report into structured findings.

    Args:
        report_path: Path to the gitleaks JSON output file.
        repo: Repo dict for enriching findings with repo metadata.

    Returns:
        List of structured finding dicts.
    """
    report_file = Path(report_path)
    if not report_file.exists() or report_file.stat().st_size == 0:
        return []

    try:
        with open(report_path) as f:
            raw_findings = json.load(f)
    except json.JSONDecodeError:
        logger.warning("Failed to parse gitleaks report for %s", repo["full_name"])
        return []

    if not isinstance(raw_findings, list):
        return []

    findings: list[dict[str, Any]] = []
    for raw in raw_findings:
        findings.append({
            "repo": repo["full_name"],
            "rule_id": raw.get("RuleID", "unknown"),
            "description": raw.get("Description", ""),
            "severity": _classify_severity(raw.get("RuleID", "")),
            "file": raw.get("File", ""),
            "line": raw.get("StartLine", 0),
            "commit": raw.get("Commit", ""),
            "snippet": raw.get("Match", "") if full_matches else _truncate(raw.get("Match", ""), 200),
            "author": raw.get("Author", ""),
            "date": raw.get("Date", ""),
            "tags": raw.get("Tags", []),
        })

    return findings


def _classify_severity(rule_id: str) -> str:
    """Classify a finding's severity based on rule ID.

    Args:
        rule_id: The gitleaks rule identifier.

    Returns:
        Severity string: critical, high, medium, or low.
    """
    critical_rules = {"aws-access-token", "github-pat", "private-key", "generic-api-key"}
    high_rules = {"aws-secret-key", "gcp-api-key", "slack-token", "stripe-api-key"}
    low_rules = {"pii-email", "pii-phone", "private-ip"}

    rule_lower = rule_id.lower()
    if rule_lower in critical_rules:
        return "critical"
    elif rule_lower in high_rules:
        return "high"
    elif rule_lower in low_rules:
        return "low"
    return "medium"


def _truncate(text: str, max_len: int) -> str:
    """Truncate text to max length, adding ellipsis if needed.

    Args:
        text: Text to truncate.
        max_len: Maximum allowed length.

    Returns:
        Truncated text.
    """
    if len(text) <= max_len:
        return text
    return text[:max_len - 3] + "..."
