"""Repository discovery via GitHub and GitLab APIs."""

import logging
import os
from typing import Any

import requests

logger = logging.getLogger(__name__)


def discover_github_repos(username: str, token: str | None = None) -> list[dict[str, Any]]:
    """Discover repositories for a GitHub user.

    Uses authenticated endpoint when token is provided (includes private repos).
    Falls back to public endpoint otherwise.

    Args:
        username: GitHub username to discover repos for.
        token: Optional GitHub PAT for private repo access.

    Returns:
        List of repo dicts with keys: name, full_name, clone_url, private, provider.
    """
    headers: dict[str, str] = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    repos: list[dict[str, Any]] = []

    if token:
        # Authenticated: get all repos the token can see, then filter by owner
        url = "https://api.github.com/user/repos?visibility=all&per_page=100&affiliation=owner"
    else:
        url = f"https://api.github.com/users/{username}/repos?type=public&per_page=100"

    while url:
        logger.debug("Fetching: %s", url)
        resp = requests.get(url, headers=headers, timeout=30)
        resp.raise_for_status()

        for repo in resp.json():
            # When using authenticated endpoint, filter to requested owner
            if token and repo.get("owner", {}).get("login", "").lower() != username.lower():
                continue
            repos.append({
                "name": repo["name"],
                "full_name": repo["full_name"],
                "clone_url": repo["clone_url"],
                "private": repo.get("private", False),
                "provider": "github",
            })

        # Handle pagination via Link header
        url = _parse_next_link(resp.headers.get("Link", ""))

    logger.info("Discovered %d repos for GitHub user '%s'", len(repos), username)
    return repos


def discover_all_github_repos() -> list[dict[str, Any]]:
    """Discover repos for all configured GitHub users.

    Reads GITHUB_USERS and GITHUB_TOKEN from environment.

    Returns:
        Combined list of repo dicts across all users.
    """
    users_raw = os.environ.get("GITHUB_USERS", "")
    if not users_raw.strip():
        return []

    token = os.environ.get("GITHUB_TOKEN")
    usernames = [u.strip() for u in users_raw.split(",") if u.strip()]

    all_repos: list[dict[str, Any]] = []
    for username in usernames:
        try:
            repos = discover_github_repos(username, token)
            all_repos.extend(repos)
        except requests.RequestException as e:
            logger.error("Failed to discover repos for '%s': %s", username, e)
            raise

    return all_repos


def discover_gitlab_repos(username: str, token: str | None = None) -> list[dict[str, Any]]:
    """Discover repositories for a GitLab user.

    Uses authenticated endpoint when token is provided (includes private repos).
    Falls back to public endpoint otherwise.

    Args:
        username: GitLab username.
        token: Optional GitLab PAT for private repo access.

    Returns:
        List of repo dicts with keys: name, full_name, clone_url, private, provider.
    """
    headers: dict[str, str] = {}
    if token:
        headers["PRIVATE-TOKEN"] = token

    repos: list[dict[str, Any]] = []

    if token:
        # Authenticated: get all projects the user is a member of, filter by owner
        url = "https://gitlab.com/api/v4/projects?membership=true&per_page=100"
    else:
        # Public: get user's public projects
        url = f"https://gitlab.com/api/v4/users/{username}/projects?visibility=public&per_page=100"

    page = 1
    while url:
        logger.debug("Fetching GitLab: %s", url)
        resp = requests.get(url, headers=headers, timeout=30)
        resp.raise_for_status()

        for project in resp.json():
            # When authenticated, filter to repos owned by the requested username
            namespace = project.get("namespace", {})
            owner_path = namespace.get("path", "").lower()
            if token and owner_path != username.lower():
                continue

            path_with_namespace = project.get("path_with_namespace", "")
            repos.append({
                "name": project["path"],
                "full_name": path_with_namespace,
                "clone_url": project.get("http_url_to_repo", f"https://gitlab.com/{path_with_namespace}.git"),
                "private": project.get("visibility", "public") != "public",
                "provider": "gitlab",
            })

        # Handle pagination via X-Next-Page header or Link header
        next_page = resp.headers.get("X-Next-Page", "")
        if next_page and next_page.strip():
            page = int(next_page)
            # Rebuild URL with new page number
            if "?" in url:
                base_url = url.split("&page=")[0] if "&page=" in url else url
                url = f"{base_url}&page={page}"
            else:
                url = f"{url}?page={page}"
        else:
            # Also try Link header as fallback
            url = _parse_next_link(resp.headers.get("Link", ""))

    logger.info("Discovered %d repos for GitLab user '%s'", len(repos), username)
    return repos


def discover_all_gitlab_repos() -> list[dict[str, Any]]:
    """Discover repos for all configured GitLab users.

    Reads GITLAB_USERS and GITLAB_TOKEN from environment.

    Returns:
        Combined list of repo dicts across all GitLab users.
        Returns empty list if GITLAB_USERS is not set (GitLab is optional).
    """
    users_raw = os.environ.get("GITLAB_USERS", "")
    if not users_raw.strip():
        logger.debug("GITLAB_USERS not set, skipping GitLab discovery")
        return []

    token = os.environ.get("GITLAB_TOKEN")
    usernames = [u.strip() for u in users_raw.split(",") if u.strip()]

    all_repos: list[dict[str, Any]] = []
    for username in usernames:
        try:
            repos = discover_gitlab_repos(username, token)
            all_repos.extend(repos)
        except requests.RequestException as e:
            logger.error("Failed to discover GitLab repos for '%s': %s", username, e)
            raise

    return all_repos


def discover_all_repos() -> list[dict[str, Any]]:
    """Discover repos from all configured providers (GitHub + GitLab + direct URLs).

    At least one source must be configured: GITHUB_USERS, GITLAB_USERS, or REPO_URLS.

    Returns:
        Combined list of repo dicts across all providers.
    """
    all_repos: list[dict[str, Any]] = []
    has_source = False

    # Direct repo URLs (optional)
    repo_urls = _parse_repo_urls()
    if repo_urls:
        has_source = True
        all_repos.extend(repo_urls)
        logger.info("Direct URLs: %d repos", len(repo_urls))

    # GitHub (optional if REPO_URLS provided)
    github_users = os.environ.get("GITHUB_USERS", "").strip()
    if github_users:
        has_source = True
        github_repos = discover_all_github_repos()
        all_repos.extend(github_repos)
        logger.info("GitHub: discovered %d repos", len(github_repos))

    # GitLab (optional)
    try:
        gitlab_repos = discover_all_gitlab_repos()
        if gitlab_repos:
            has_source = True
            all_repos.extend(gitlab_repos)
            logger.info("GitLab: discovered %d repos", len(gitlab_repos))
    except Exception as e:
        logger.error("GitLab discovery failed (continuing without): %s", e)

    if not has_source:
        raise ValueError(
            "No repo sources configured. Set GITHUB_USERS, GITLAB_USERS, or REPO_URLS."
        )

    return all_repos


def _parse_repo_urls() -> list[dict[str, Any]]:
    """Parse direct repo URLs from the REPO_URLS environment variable.

    Accepts comma-separated or newline-separated URLs.
    Supports GitHub and GitLab HTTPS URLs.

    Returns:
        List of repo dicts with keys: name, full_name, clone_url, private, provider.
    """
    raw = os.environ.get("REPO_URLS", "")
    if not raw.strip():
        return []

    import re
    repos: list[dict[str, Any]] = []
    # Split on commas, newlines, or semicolons
    urls = re.split(r"[,\n;]+", raw)

    for url in urls:
        url = url.strip()
        if not url:
            continue

        # Normalize: strip trailing .git
        clone_url = url if url.endswith(".git") else url + ".git"

        # Parse provider and name from URL
        # https://github.com/user/repo or https://gitlab.com/user/repo
        match = re.match(r"https?://(github\.com|gitlab\.com)/(.+?)(?:\.git)?$", url)
        if match:
            provider = "github" if "github" in match.group(1) else "gitlab"
            full_name = match.group(2).rstrip("/")
            name = full_name.split("/")[-1]
        else:
            # Unknown provider — still try to clone
            provider = "unknown"
            full_name = url.split("//")[-1].rstrip("/")
            name = full_name.split("/")[-1].replace(".git", "")

        repos.append({
            "name": name,
            "full_name": full_name,
            "clone_url": clone_url,
            "private": False,
            "provider": provider,
        })
        logger.debug("Parsed repo URL: %s → %s (%s)", url, full_name, provider)

    return repos


def _parse_next_link(link_header: str) -> str | None:
    """Parse the 'next' URL from a Link header (GitHub/GitLab).

    Args:
        link_header: Raw Link header value.

    Returns:
        Next page URL or None if no next page.
    """
    if not link_header:
        return None

    for part in link_header.split(","):
        part = part.strip()
        if 'rel="next"' in part:
            # Extract URL between < and >
            start = part.index("<") + 1
            end = part.index(">")
            return part[start:end]
    return None
