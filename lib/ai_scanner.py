"""AI-powered security scanner using AWS Bedrock / Claude.

Extracts repository content and sends it to Claude for contextual
PII, secret, and security analysis that regex-based tools can't catch.
"""

import json
import logging
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# File extensions to include in AI analysis
TEXT_EXTENSIONS = {
    ".md", ".txt", ".yml", ".yaml", ".json", ".toml", ".cfg", ".ini",
    ".sh", ".py", ".js", ".rb", ".go", ".ts",
}
# Also match .env* files by prefix
ENV_PREFIX = ".env"

MAX_FILE_SIZE = 100 * 1024  # 100KB
MAX_CONTENT_CHARS = 80_000  # ~fits in Claude context window
MAX_COMMIT_MESSAGES = 50

CLAUDE_PROMPT = """\
You are a security auditor specializing in PII and secret detection in source code repositories.

Analyze the following repository content and identify:
1. PII: real names, email addresses, phone numbers, physical addresses, account IDs, usernames tied to real people
2. Hardcoded secrets: API keys, passwords, tokens, connection strings that appear to be real (not placeholders)
3. Infrastructure details: internal IPs, hostnames, network topology that shouldn't be public
4. Sensitive context: comments or documentation revealing personal relationships, habits, home locations

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

Only report genuine issues — ignore placeholder values, example configs, and test data that is clearly not real.
"""


def scan_repo_with_ai(repo: dict[str, Any], extra_prompt: str = "") -> list[dict[str, Any]]:
    """Run AI-powered security scan on a single repository.

    Extracts text content from the repo's HEAD, sends it to Claude
    via Bedrock, and parses the structured findings response.

    Args:
        repo: Repo dict with 'local_path', 'name', 'full_name' keys.
        extra_prompt: Additional prompt text (e.g. user exclusions).

    Returns:
        List of finding dicts with tool='ai'.
    """
    repo_name = repo["full_name"]
    logger.info("AI scanning %s", repo_name)

    try:
        content = _extract_repo_content(repo)
    except Exception as e:
        logger.error("Failed to extract content from '%s': %s", repo_name, e)
        return []

    if not content.strip():
        logger.warning("No extractable content in '%s', skipping AI scan", repo_name)
        return []

    char_count = len(content)
    logger.info(
        "Extracted ~%d chars from '%s' (est. ~%d tokens)",
        char_count, repo_name, char_count // 4,
    )

    try:
        raw_response = _call_bedrock(content, extra_prompt=extra_prompt)
    except Exception as e:
        logger.error("Bedrock API call failed for '%s': %s", repo_name, e)
        return []

    try:
        findings = _parse_ai_response(raw_response, repo)
    except Exception as e:
        logger.error("Failed to parse AI response for '%s': %s", repo_name, e)
        return []

    logger.info("AI found %d findings in '%s'", len(findings), repo_name)
    return findings


def scan_all_repos_with_ai(repos: list[dict[str, Any]], extra_prompt: str = "") -> list[dict[str, Any]]:
    """Run AI scan across all repos sequentially.

    Processes repos one at a time to respect Bedrock rate limits.
    If a single repo fails, logs the error and continues.

    Args:
        repos: List of repo dicts with 'local_path' key.
        extra_prompt: Additional prompt text (e.g. user exclusions).

    Returns:
        Combined list of all AI findings across repos.
    """
    all_findings: list[dict[str, Any]] = []
    total = len(repos)

    for i, repo in enumerate(repos, 1):
        logger.info("AI scan progress: %d/%d — %s", i, total, repo["full_name"])
        findings = scan_repo_with_ai(repo, extra_prompt=extra_prompt)
        all_findings.extend(findings)

    logger.info("AI scanning complete: %d total findings across %d repos", len(all_findings), total)
    return all_findings


def _extract_repo_content(repo: dict[str, Any]) -> str:
    """Extract text content from a mirrored repo for AI analysis.

    Checks out HEAD into a temp directory, collects candidate files,
    and also extracts recent commit messages.

    Args:
        repo: Repo dict with 'local_path'.

    Returns:
        Concatenated content string capped at MAX_CONTENT_CHARS.
    """
    local_path = repo["local_path"]
    parts: list[str] = []
    total_chars = 0

    with tempfile.TemporaryDirectory(prefix="ai-scan-") as tmpdir:
        # Checkout HEAD to temp directory
        try:
            subprocess.run(
                ["git", "-C", local_path, "worktree", "add", "--detach", tmpdir, "HEAD"],
                capture_output=True, text=True, check=True, timeout=60,
            )
        except subprocess.CalledProcessError as e:
            logger.warning("Worktree add failed for '%s', trying archive: %s", repo["full_name"], e.stderr.strip())
            # Fallback: use git archive
            subprocess.run(
                ["git", "-C", local_path, "archive", "--format=tar", "HEAD"],
                capture_output=True, check=True, timeout=60,
            )
            # If archive also fails, let the exception propagate
            return _extract_via_archive(local_path, tmpdir, repo)

        try:
            # Collect candidate files
            for file_path in sorted(Path(tmpdir).rglob("*")):
                if total_chars >= MAX_CONTENT_CHARS:
                    break
                if not file_path.is_file():
                    continue
                if file_path.stat().st_size > MAX_FILE_SIZE:
                    continue
                if not _is_candidate_file(file_path):
                    continue
                # Skip .git directory
                try:
                    file_path.relative_to(Path(tmpdir) / ".git")
                    continue
                except ValueError:
                    pass  # Not in .git, good

                rel_path = file_path.relative_to(tmpdir)
                try:
                    content = file_path.read_text(errors="ignore")
                except Exception:
                    continue

                header = f"\n--- FILE: {rel_path} ---\n"
                chunk = header + content
                if total_chars + len(chunk) > MAX_CONTENT_CHARS:
                    remaining = MAX_CONTENT_CHARS - total_chars
                    chunk = chunk[:remaining]
                parts.append(chunk)
                total_chars += len(chunk)
        finally:
            # Clean up worktree
            subprocess.run(
                ["git", "-C", local_path, "worktree", "remove", "--force", tmpdir],
                capture_output=True, text=True, timeout=30,
            )

    # Add commit messages
    commit_section = _extract_commit_messages(local_path)
    if commit_section and total_chars < MAX_CONTENT_CHARS:
        remaining = MAX_CONTENT_CHARS - total_chars
        parts.append(commit_section[:remaining])

    return "".join(parts)


def _extract_via_archive(local_path: str, tmpdir: str, repo: dict[str, Any]) -> str:
    """Fallback extraction using git archive + tar.

    Args:
        local_path: Path to the bare mirror repo.
        tmpdir: Temp directory to extract into.
        repo: Repo dict for logging.

    Returns:
        Concatenated content string.
    """
    import tarfile
    import io

    result = subprocess.run(
        ["git", "-C", local_path, "archive", "--format=tar", "HEAD"],
        capture_output=True, check=True, timeout=120,
    )

    tar = tarfile.open(fileobj=io.BytesIO(result.stdout))
    tar.extractall(path=tmpdir)
    tar.close()

    parts: list[str] = []
    total_chars = 0

    for file_path in sorted(Path(tmpdir).rglob("*")):
        if total_chars >= MAX_CONTENT_CHARS:
            break
        if not file_path.is_file():
            continue
        if file_path.stat().st_size > MAX_FILE_SIZE:
            continue
        if not _is_candidate_file(file_path):
            continue

        rel_path = file_path.relative_to(tmpdir)
        try:
            content = file_path.read_text(errors="ignore")
        except Exception:
            continue

        header = f"\n--- FILE: {rel_path} ---\n"
        chunk = header + content
        if total_chars + len(chunk) > MAX_CONTENT_CHARS:
            remaining = MAX_CONTENT_CHARS - total_chars
            chunk = chunk[:remaining]
        parts.append(chunk)
        total_chars += len(chunk)

    commit_section = _extract_commit_messages(local_path)
    if commit_section and total_chars < MAX_CONTENT_CHARS:
        remaining = MAX_CONTENT_CHARS - total_chars
        parts.append(commit_section[:remaining])

    return "".join(parts)


def _is_candidate_file(file_path: Path) -> bool:
    """Check if a file is a candidate for AI analysis.

    Args:
        file_path: Path to check.

    Returns:
        True if the file should be included.
    """
    name = file_path.name
    suffix = file_path.suffix.lower()

    # Match .env* files
    if name.startswith(ENV_PREFIX):
        return True

    return suffix in TEXT_EXTENSIONS


def _extract_commit_messages(local_path: str) -> str:
    """Extract recent commit messages from a repo.

    Args:
        local_path: Path to the bare mirror repo.

    Returns:
        Formatted string of commit messages, or empty string on failure.
    """
    try:
        result = subprocess.run(
            [
                "git", "-C", local_path, "log",
                f"--max-count={MAX_COMMIT_MESSAGES}",
                "--format=%H %an <%ae> %s",
            ],
            capture_output=True, text=True, check=True, timeout=30,
        )
        if result.stdout.strip():
            return f"\n--- RECENT COMMIT MESSAGES (last {MAX_COMMIT_MESSAGES}) ---\n{result.stdout}"
    except subprocess.CalledProcessError as e:
        logger.warning("Failed to extract commit messages: %s", e.stderr.strip() if e.stderr else str(e))
    return ""


def _call_bedrock(content: str, extra_prompt: str = "") -> str:
    """Send content to Claude via AWS Bedrock and return the response.

    Args:
        content: Repository content to analyze.

    Returns:
        Raw text response from Claude.

    Raises:
        Exception: On any Bedrock API error.
    """
    import boto3

    region = os.environ.get("AWS_REGION", "us-east-1")
    model_id = os.environ.get("BEDROCK_MODEL_ID", "us.anthropic.claude-opus-4-6-v1")

    client = boto3.client("bedrock-runtime", region_name=region)

    logger.debug("Calling Bedrock model '%s' in region '%s'", model_id, region)

    response = client.converse(
        modelId=model_id,
        messages=[
            {
                "role": "user",
                "content": [
                    {"text": f"{CLAUDE_PROMPT}{extra_prompt}\n\n--- REPOSITORY CONTENT ---\n{content}"}
                ],
            }
        ],
        inferenceConfig={
            "maxTokens": 8192,
            "temperature": 0.0,
        },
    )

    # Extract text from Converse API response
    output = response.get("output", {})
    message = output.get("message", {})
    content_blocks = message.get("content", [])
    text = "\n".join(b["text"] for b in content_blocks if "text" in b)
    logger.debug("Bedrock response length: %d chars", len(text))
    return text


def _parse_ai_response(response_text: str, repo: dict[str, Any]) -> list[dict[str, Any]]:
    """Parse Claude's JSON response into structured findings.

    Handles cases where Claude wraps JSON in markdown code blocks.

    Args:
        response_text: Raw text from Claude.
        repo: Repo dict for enriching findings.

    Returns:
        List of structured finding dicts.
    """
    # Strip markdown code blocks if present
    text = response_text.strip()
    if text.startswith("```"):
        # Remove opening ```json or ```
        first_newline = text.index("\n")
        text = text[first_newline + 1:]
        if text.endswith("```"):
            text = text[:-3]
        text = text.strip()

    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        # Try to find JSON object in the response
        start = text.find("{")
        end = text.rfind("}") + 1
        if start >= 0 and end > start:
            data = json.loads(text[start:end])
        else:
            logger.warning("Could not parse AI response as JSON for '%s'", repo["full_name"])
            return []

    raw_findings = data.get("findings", [])
    if not isinstance(raw_findings, list):
        return []

    findings: list[dict[str, Any]] = []
    for raw in raw_findings:
        findings.append({
            "repo": repo["full_name"],
            "tool": "ai",
            "rule_id": f"ai-{raw.get('category', 'unknown')}",
            "description": raw.get("description", ""),
            "severity": raw.get("severity", "medium"),
            "category": raw.get("category", "unknown"),
            "file": raw.get("file", ""),
            "line": raw.get("line", 0),
            "commit": "",
            "snippet": raw.get("snippet", "")[:200],
            "recommendation": raw.get("recommendation", ""),
            "author": "",
            "date": "",
            "tags": [raw.get("category", "ai")],
        })

    return findings
