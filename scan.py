#!/usr/bin/env python3
"""Repo Security Scanner — CLI entrypoint.

Discovers GitHub and GitLab repositories, clones them, and scans for
secrets/PII using gitleaks and AI (Claude via Bedrock). Outputs JSON
and Markdown reports, with optional email delivery.

Usage:
    python scan.py [--gitleaks] [--ai] [--all] [--email] [--verbose] [--json-only]

Exit codes:
    0 — Clean scan, no findings
    1 — Findings detected
    2 — Error during execution
"""

import argparse
import logging
import sys
from pathlib import Path
from typing import NoReturn

from lib.discovery import discover_all_repos
from lib.clone_manager import clone_or_update_repos
from lib.gitleaks_scanner import scan_all_repos
from lib.ai_scanner import scan_all_repos_with_ai
from lib.report import generate_reports, get_markdown_content
from lib.email_reporter import send_email_report
from lib.user_ignores import load_user_ignores, filter_gitleaks_findings, get_ai_exclusion_prompt

logger = logging.getLogger("repo-security-scanner")


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments.

    Returns:
        Parsed argument namespace.
    """
    parser = argparse.ArgumentParser(
        description="Scan GitHub/GitLab repositories for secrets and PII using gitleaks and AI.",
        prog="repo-security-scanner",
    )
    scan_group = parser.add_argument_group("scanner selection")
    scan_group.add_argument(
        "--gitleaks",
        action="store_true",
        help="Run gitleaks scan only (default when no flags given)",
    )
    scan_group.add_argument(
        "--ai",
        action="store_true",
        help="Run AI scan only (Claude via Bedrock)",
    )
    scan_group.add_argument(
        "--all",
        action="store_true",
        help="Run all available scanners (gitleaks + AI)",
    )
    parser.add_argument(
        "--email",
        action="store_true",
        help="Send email report after scan (requires SMTP env vars)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose (DEBUG) logging",
    )
    parser.add_argument(
        "--json-only",
        action="store_true",
        help="Output JSON report only, skip Markdown",
    )
    parser.add_argument(
        "--full-matches",
        action="store_true",
        help="Show full untruncated match content in findings (default truncates to 200 chars)",
    )
    return parser.parse_args()


def setup_logging(verbose: bool = False) -> None:
    """Configure logging for the application.

    Args:
        verbose: If True, set level to DEBUG. Otherwise INFO.
    """
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        stream=sys.stdout,
    )


def _determine_scanners(args: argparse.Namespace) -> tuple[bool, bool]:
    """Determine which scanners to run based on CLI flags.

    Default (no flags): run gitleaks only. AI requires explicit --ai or --all.

    Args:
        args: Parsed CLI arguments.

    Returns:
        Tuple of (run_gitleaks, run_ai).
    """
    if args.all:
        return True, True
    if args.ai and not args.gitleaks:
        return False, True
    # Default (no flags) or --gitleaks: gitleaks only
    return True, False


def main() -> int:
    """Main scan pipeline: discover → clone → scan(gitleaks) → scan(ai) → report → email.

    Returns:
        Exit code: 0=clean, 1=findings, 2=error.
    """
    args = parse_args()
    setup_logging(verbose=args.verbose)

    run_gitleaks, run_ai = _determine_scanners(args)
    scanners = []
    if run_gitleaks:
        scanners.append("gitleaks")
    if run_ai:
        scanners.append("ai")
    scanner_label = " + ".join(scanners)

    logger.info("Starting repository security scan (Phase 2 — %s)", scanner_label)

    # Step 1: Discover repos (GitHub + GitLab)
    logger.info("Step 1: Discovering repositories...")
    try:
        repos = discover_all_repos()
    except Exception as e:
        logger.error("Repository discovery failed: %s", e)
        return 2

    if not repos:
        logger.warning("No repositories found. Check GITHUB_USERS / GITLAB_USERS env vars.")
        return 2

    github_count = sum(1 for r in repos if r.get("provider") == "github")
    gitlab_count = sum(1 for r in repos if r.get("provider") == "gitlab")
    logger.info("Discovered %d repositories (GitHub: %d, GitLab: %d)", len(repos), github_count, gitlab_count)

    # Step 2: Clone / update repos
    logger.info("Step 2: Cloning/updating repositories...")
    try:
        cloned_repos = clone_or_update_repos(repos)
    except Exception as e:
        logger.error("Clone/update failed: %s", e)
        return 2

    logger.info("Cloned/updated %d repositories", len(cloned_repos))

    all_findings: list[dict] = []

    # Load user ignores (personal exclusions)
    user_ignores = load_user_ignores()

    # Step 3: Scan with gitleaks
    if run_gitleaks:
        logger.info("Step 3: Scanning with gitleaks...")
        try:
            gitleaks_findings = scan_all_repos(cloned_repos, full_matches=args.full_matches)
            # Tag gitleaks findings with tool source
            for f in gitleaks_findings:
                f.setdefault("tool", "gitleaks")
            # Apply user exclusions
            gitleaks_findings = filter_gitleaks_findings(
                gitleaks_findings,
                user_ignores["gitleaks_patterns"],
                file_excludes=user_ignores["file_excludes"],
                rule_excludes=user_ignores["rule_excludes"],
            )
            all_findings.extend(gitleaks_findings)
            logger.info("Gitleaks: %d findings", len(gitleaks_findings))
        except Exception as e:
            logger.error("Gitleaks scanning failed: %s", e)
            return 2
    else:
        logger.info("Step 3: Skipping gitleaks (not selected)")

    # Step 4: Scan with AI
    if run_ai:
        logger.info("Step 4: Scanning with AI (Claude via Bedrock)...")
        try:
            ai_exclusion_prompt = get_ai_exclusion_prompt(user_ignores["ai_exclusions"])
            ai_findings = scan_all_repos_with_ai(cloned_repos, extra_prompt=ai_exclusion_prompt)
            all_findings.extend(ai_findings)
            logger.info("AI: %d findings", len(ai_findings))
        except Exception as e:
            logger.error("AI scanning failed (continuing with other results): %s", e)
    else:
        logger.info("Step 4: Skipping AI scan (not selected)")

    # Step 5: Generate reports
    logger.info("Step 5: Generating reports...")
    try:
        report_paths = generate_reports(
            findings=all_findings,
            repos_scanned=cloned_repos,
            json_only=args.json_only,
        )
    except Exception as e:
        logger.error("Report generation failed: %s", e)
        return 2

    # Step 6: Email report (if requested)
    if args.email:
        logger.info("Step 6: Sending email report...")
        md_content = get_markdown_content(all_findings, cloned_repos)
        send_email_report(
            findings=all_findings,
            repos_scanned=cloned_repos,
            markdown_content=md_content,
        )
    else:
        logger.info("Step 6: Skipping email (not requested)")

    # Summary
    logger.info("=" * 60)
    logger.info("SCAN COMPLETE")
    logger.info("Scanners: %s", scanner_label)
    logger.info("Repos scanned: %d", len(cloned_repos))
    logger.info("Total findings: %d", len(all_findings))
    if run_gitleaks:
        gl_count = sum(1 for f in all_findings if f.get("tool") == "gitleaks")
        logger.info("  Gitleaks findings: %d", gl_count)
    if run_ai:
        ai_count = sum(1 for f in all_findings if f.get("tool") == "ai")
        logger.info("  AI findings: %d", ai_count)
    for path_type, path in report_paths.items():
        logger.info("Report (%s): %s", path_type, path)
    logger.info("=" * 60)

    return 1 if all_findings else 0


if __name__ == "__main__":
    sys.exit(main())
