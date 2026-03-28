"""Git clone and fetch manager for mirrored repositories."""

import logging
import os
import subprocess
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

DEFAULT_REPO_BASE = "/data/repos"


def clone_or_update_repos(
    repos: list[dict[str, Any]],
    base_path: str = DEFAULT_REPO_BASE,
) -> list[dict[str, Any]]:
    """Clone or update a list of repositories as bare mirrors.

    First run: git clone --mirror
    Subsequent runs: git fetch --all --prune

    Args:
        repos: List of repo dicts from discovery (must have clone_url, name, provider).
        base_path: Base directory for storing mirrored repos.

    Returns:
        List of repo dicts augmented with 'local_path' and 'cached' keys.
    """
    github_token = os.environ.get("GITHUB_TOKEN")
    gitlab_token = os.environ.get("GITLAB_TOKEN")
    results: list[dict[str, Any]] = []

    for repo in repos:
        provider = repo.get("provider", "github")
        repo_dir = Path(base_path) / provider / f"{repo['name']}.git"

        clone_url = repo["clone_url"]
        # Inject token for private repos
        if provider == "github" and github_token and repo.get("private") and "github.com" in clone_url:
            clone_url = clone_url.replace("https://", f"https://x-access-token:{github_token}@")
        elif provider == "gitlab" and gitlab_token and "gitlab.com" in clone_url:
            clone_url = clone_url.replace("https://", f"https://oauth2:{gitlab_token}@")

        try:
            if repo_dir.exists():
                _fetch_repo(repo_dir, clone_url)
                cached = True
            else:
                _clone_repo(clone_url, repo_dir)
                cached = False

            results.append({
                **repo,
                "local_path": str(repo_dir),
                "cached": cached,
            })
        except subprocess.CalledProcessError as e:
            logger.error(
                "Git operation failed for '%s': %s",
                repo["full_name"],
                e.stderr.strip() if e.stderr else str(e),
            )
            raise

    return results


def _clone_repo(clone_url: str, repo_dir: Path) -> None:
    """Clone a repository as a bare mirror.

    Args:
        clone_url: Git clone URL (may include token).
        repo_dir: Local path for the mirrored repo.
    """
    repo_dir.parent.mkdir(parents=True, exist_ok=True)
    logger.info("Cloning %s", _redact_url(clone_url))
    subprocess.run(
        ["git", "clone", "--mirror", clone_url, str(repo_dir)],
        capture_output=True,
        text=True,
        check=True,
        timeout=300,
    )


def _fetch_repo(repo_dir: Path, clone_url: str) -> None:
    """Fetch updates for an existing mirrored repo.

    Args:
        repo_dir: Local path to the mirrored repo.
        clone_url: Git remote URL (used to update origin if needed).
    """
    logger.info("Updating cached repo at %s", repo_dir)

    # Update the remote URL in case token changed
    subprocess.run(
        ["git", "-C", str(repo_dir), "remote", "set-url", "origin", clone_url],
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    )

    subprocess.run(
        ["git", "-C", str(repo_dir), "fetch", "--all", "--prune"],
        capture_output=True,
        text=True,
        check=True,
        timeout=300,
    )


def _redact_url(url: str) -> str:
    """Redact tokens from URLs for safe logging.

    Args:
        url: URL that may contain embedded credentials.

    Returns:
        URL with credentials replaced by [REDACTED].
    """
    if "@" in url and "://" in url:
        protocol_end = url.index("://") + 3
        at_pos = url.index("@")
        return url[:protocol_end] + "[REDACTED]@" + url[at_pos + 1:]
    return url
