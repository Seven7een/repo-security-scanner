"""User-level scan exclusions loader.

Loads user-ignores.toml (not committed) for personal allowlist patterns
and AI prompt exclusions. Falls back gracefully if file doesn't exist.
"""

import logging
import re
from pathlib import Path
from typing import Any

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib  # type: ignore[no-redef]

logger = logging.getLogger(__name__)

# Check both /app (Docker) and local paths
IGNORES_PATHS = [
    Path("/app/user-ignores.toml"),
    Path("user-ignores.toml"),
]


def load_user_ignores() -> dict[str, Any]:
    """Load user-ignores.toml from known paths.

    Returns:
        Dict with 'gitleaks_patterns', 'file_excludes', 'rule_excludes',
        and 'ai_exclusions'. Empty lists if file not found.
    """
    empty = {"gitleaks_patterns": [], "file_excludes": [], "rule_excludes": [], "ai_exclusions": []}

    for path in IGNORES_PATHS:
        if path.exists():
            logger.info("Loading user ignores from %s", path)
            try:
                with open(path, "rb") as f:
                    config = tomllib.load(f)
                result = {
                    "gitleaks_patterns": config.get("gitleaks_allowlist", {}).get("patterns", []),
                    "file_excludes": config.get("gitleaks_file_excludes", {}).get("patterns", []),
                    "rule_excludes": config.get("gitleaks_rule_excludes", {}).get("rules", []),
                    "ai_exclusions": config.get("ai_exclusions", {}).get("notes", []),
                }
                logger.info(
                    "Loaded: %d allowlist patterns, %d file excludes, %d rule excludes, %d AI exclusions",
                    len(result["gitleaks_patterns"]),
                    len(result["file_excludes"]),
                    len(result["rule_excludes"]),
                    len(result["ai_exclusions"]),
                )
                return result
            except Exception as e:
                logger.warning("Failed to parse user-ignores.toml: %s", e)
                return empty

    logger.debug("No user-ignores.toml found, proceeding without exclusions")
    return empty


def filter_gitleaks_findings(
    findings: list[dict[str, Any]],
    patterns: list[str],
    file_excludes: list[str] | None = None,
    rule_excludes: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Remove gitleaks findings that match user allowlist patterns, file patterns, or rule IDs.

    Args:
        findings: List of finding dicts.
        patterns: List of regex patterns to exclude (matched against snippet + author).
        file_excludes: List of regex patterns to exclude by file path.
        rule_excludes: List of rule IDs to exclude entirely.

    Returns:
        Filtered findings list.
    """
    compiled = [re.compile(p, re.IGNORECASE) for p in patterns] if patterns else []
    file_compiled = [re.compile(p, re.IGNORECASE) for p in (file_excludes or [])]
    rule_set = {r.lower() for r in (rule_excludes or [])}

    filtered = []
    excluded = 0

    for f in findings:
        # Rule exclusion
        if f.get("rule_id", "").lower() in rule_set:
            excluded += 1
            continue

        # File exclusion
        file_path = f.get("file", "")
        if file_compiled and any(rx.search(file_path) for rx in file_compiled):
            excluded += 1
            continue

        # Snippet/author pattern exclusion
        snippet = f.get("snippet", "")
        author = f.get("author", "")
        match_text = f"{snippet} {author}"
        if compiled and any(rx.search(match_text) for rx in compiled):
            excluded += 1
            continue

        filtered.append(f)

    if excluded:
        logger.info("User ignores: excluded %d gitleaks findings", excluded)

    return filtered


def get_ai_exclusion_prompt(exclusions: list[str]) -> str:
    """Build an AI prompt addendum from user exclusions.

    Args:
        exclusions: List of exclusion notes.

    Returns:
        String to append to the AI scanner prompt, or empty string.
    """
    if not exclusions:
        return ""

    lines = "\n".join(f"- {note}" for note in exclusions)
    return (
        f"\n\nKNOWN SAFE — Do NOT flag these as findings:\n{lines}\n"
    )
