"""Report generator — JSON and Markdown output for scan findings."""

import json
import logging
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

DEFAULT_OUTPUT_DIR = "/output"


def generate_reports(
    findings: list[dict[str, Any]],
    repos_scanned: list[dict[str, Any]],
    output_dir: str = DEFAULT_OUTPUT_DIR,
    json_only: bool = False,
) -> dict[str, str]:
    """Generate JSON and optionally Markdown reports.

    Args:
        findings: List of finding dicts from all scanners.
        repos_scanned: List of repo dicts that were scanned.
        output_dir: Directory to write reports to.
        json_only: If True, skip Markdown generation.

    Returns:
        Dict with keys 'json' and optionally 'markdown' pointing to file paths.
    """
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    scan_metadata = _build_metadata(findings, repos_scanned)

    # JSON report
    json_path = out / "findings.json"
    json_data = {
        "metadata": scan_metadata,
        "findings": findings,
    }
    with open(json_path, "w") as f:
        json.dump(json_data, f, indent=2, default=str)
    logger.info("JSON report written to %s", json_path)

    result = {"json": str(json_path)}

    # Markdown report
    if not json_only:
        md_path = out / "report.md"
        md_content = _build_markdown(scan_metadata, findings, repos_scanned)
        with open(md_path, "w") as f:
            f.write(md_content)
        logger.info("Markdown report written to %s", md_path)
        result["markdown"] = str(md_path)

    return result


def get_markdown_content(
    findings: list[dict[str, Any]],
    repos_scanned: list[dict[str, Any]],
) -> str:
    """Generate markdown report content without writing to file.

    Useful for email reporting.

    Args:
        findings: All findings from the scan.
        repos_scanned: All repos that were scanned.

    Returns:
        Markdown report string.
    """
    metadata = _build_metadata(findings, repos_scanned)
    return _build_markdown(metadata, findings, repos_scanned)


def _build_metadata(
    findings: list[dict[str, Any]],
    repos_scanned: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build scan metadata summary.

    Args:
        findings: All findings from the scan.
        repos_scanned: All repos that were scanned.

    Returns:
        Metadata dict with counts and timestamp.
    """
    severity_counts = Counter(f.get("severity", "unknown") for f in findings)
    tool_counts = Counter(f.get("tool", "gitleaks") for f in findings)
    return {
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "repos_scanned": len(repos_scanned),
        "total_findings": len(findings),
        "severity_counts": dict(severity_counts),
        "tool_counts": dict(tool_counts),
        "repos_with_findings": len(set(f["repo"] for f in findings)),
    }


def _build_markdown(
    metadata: dict[str, Any],
    findings: list[dict[str, Any]],
    repos_scanned: list[dict[str, Any]],
) -> str:
    """Build a human-readable Markdown report.

    Args:
        metadata: Scan metadata dict.
        findings: All findings.
        repos_scanned: All repos scanned.

    Returns:
        Markdown string.
    """
    lines: list[str] = []

    # Determine active tools
    tool_counts = metadata.get("tool_counts", {})
    tools_used = sorted(tool_counts.keys()) if tool_counts else ["gitleaks"]
    scanner_label = " + ".join(tools_used)

    # Header
    lines.append("# 🔍 Repository Security Scan Report")
    lines.append("")
    lines.append(f"**Scan Time:** {metadata['scan_time']}")
    lines.append(f"**Scanners:** {scanner_label}")
    lines.append("")

    # Summary table
    lines.append("## Summary")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("|--------|-------|")
    lines.append(f"| Repositories Scanned | {metadata['repos_scanned']} |")
    lines.append(f"| Repos with Findings | {metadata['repos_with_findings']} |")
    lines.append(f"| Total Findings | {metadata['total_findings']} |")

    # Findings by tool
    for tool, count in sorted(tool_counts.items()):
        tool_emoji = "🤖" if tool == "ai" else "🔎"
        lines.append(f"| {tool_emoji} Findings ({tool}) | {count} |")

    severity_counts = metadata.get("severity_counts", {})
    for sev in ["critical", "high", "medium", "low"]:
        count = severity_counts.get(sev, 0)
        if count > 0:
            emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵"}.get(sev, "⚪")
            lines.append(f"| {emoji} {sev.capitalize()} | {count} |")

    lines.append("")

    # Findings grouped by repo
    if findings:
        lines.append("## Findings by Repository")
        lines.append("")

        # Group findings by repo
        by_repo: dict[str, list[dict[str, Any]]] = {}
        for f in findings:
            by_repo.setdefault(f["repo"], []).append(f)

        for repo_name, repo_findings in sorted(by_repo.items()):
            lines.append(f"### {repo_name}")
            lines.append("")
            lines.append(f"**{len(repo_findings)} finding(s)**")
            lines.append("")

            for i, f in enumerate(repo_findings, 1):
                sev = f.get("severity", "unknown")
                tool = f.get("tool", "gitleaks")
                emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵"}.get(sev, "⚪")
                tool_badge = f"[{tool}]"
                lines.append(f"**{i}. {emoji} [{sev.upper()}] {tool_badge} {f.get('rule_id', 'unknown')}**")
                lines.append(f"- **Description:** {f.get('description', 'N/A')}")
                lines.append(f"- **File:** `{f.get('file', 'N/A')}`")
                lines.append(f"- **Line:** {f.get('line', 'N/A')}")
                if f.get("commit"):
                    lines.append(f"- **Commit:** `{f['commit'][:12]}`")
                if f.get("snippet"):
                    lines.append(f"- **Match:** `{f['snippet']}`")
                if f.get("recommendation"):
                    lines.append(f"- **Recommendation:** {f['recommendation']}")
                lines.append("")
    else:
        lines.append("## ✅ No Findings")
        lines.append("")
        lines.append("No secrets or PII detected across all scanned repositories.")
        lines.append("")

    # Recommendations
    lines.append("## Recommendations")
    lines.append("")

    if any(f.get("severity") in ("critical", "high") for f in findings):
        lines.append("⚠️ **Critical/High severity findings detected. Immediate action recommended:**")
        lines.append("")
        lines.append("1. **Rotate compromised secrets immediately** — any exposed API keys, tokens, or passwords should be revoked and regenerated.")
        lines.append("2. **Audit git history** — secrets in git history remain accessible even after deletion from the current branch.")
        lines.append("3. **Consider git-filter-repo** — to permanently remove sensitive data from history if repos are public.")
        lines.append("4. **Enable pre-commit hooks** — install gitleaks as a pre-commit hook to prevent future leaks.")
    elif findings:
        lines.append("ℹ️ **Low/medium severity findings detected:**")
        lines.append("")
        lines.append("1. Review PII exposure (email addresses, phone numbers) and determine if they should be removed.")
        lines.append("2. Consider adding `.gitleaks.toml` allowlists for intentional patterns.")
        lines.append("3. Enable pre-commit hooks to catch issues before they're committed.")
    else:
        lines.append("✅ Clean scan — no action required. Consider scheduling regular scans to maintain this status.")

    lines.append("")
    lines.append("---")
    lines.append(f"*Generated by repo-security-scanner (Phase 2 — {scanner_label})*")

    return "\n".join(lines)
