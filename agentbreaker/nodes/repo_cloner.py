import os
import re
import shutil
import tempfile
from datetime import datetime

import git
import structlog

from agentbreaker.state import AgentState

log = structlog.get_logger()

SECRET_PATTERNS = [
    (re.compile(r"sk-[a-zA-Z0-9]{20,}"), "sk-***"),
    (re.compile(r"ghp_[a-zA-Z0-9]{36}"), "ghp_***"),
    (re.compile(r"(?i)(password\s*=\s*)['\"][^'\"]{4,}['\"]"), r"\1'***'"),
    (re.compile(r"(?i)(api_key\s*=\s*)['\"][^'\"]{10,}['\"]"), r"\1'***'"),
    (re.compile(r"(?i)(secret\s*=\s*)['\"][^'\"]{10,}['\"]"), r"\1'***'"),
    (re.compile(r"AIza[0-9A-Za-z\-_]{35}"), "AIza***"),
]

PRIORITY_DIRS = ["agent", "agents", "tools", "tool", "prompts", "prompt", "memory"]
INCLUDE_EXTENSIONS = {".py", ".ts", ".js", ".yaml", ".yml", ".json", ".md"}
MAX_FILES = 50


def _mask_secrets(content: str) -> tuple[str, int]:
    masked = content
    count = 0
    for pattern, replacement in SECRET_PATTERNS:
        new = pattern.sub(replacement, masked)
        if new != masked:
            count += masked.count(pattern.pattern) if hasattr(pattern, "pattern") else 1
            masked = new
    return masked, count


def _collect_files(repo_path: str) -> list[str]:
    priority = []
    rest = []

    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if not d.startswith(".") and d != "__pycache__"]
        rel_root = os.path.relpath(root, repo_path)
        is_priority = any(
            part.lower() in PRIORITY_DIRS for part in rel_root.replace("\\", "/").split("/")
        )
        for fname in files:
            ext = os.path.splitext(fname)[1].lower()
            if ext not in INCLUDE_EXTENSIONS:
                continue
            full = os.path.join(root, fname)
            (priority if is_priority else rest).append(full)

    selected = priority[:MAX_FILES]
    if len(selected) < MAX_FILES:
        selected += rest[: MAX_FILES - len(selected)]
    return selected


def repo_cloner_node(state: AgentState) -> dict:
    log.info("repo_cloner_started", repo_url=state["repo_url"])

    clone_dir = tempfile.mkdtemp(prefix="agentbreaker_")
    try:
        git.Repo.clone_from(state["repo_url"], clone_dir, depth=1)
    except git.GitCommandError as e:
        log.error("repo_clone_failed", error=str(e))
        return {
            "errors": state.get("errors", []) + [
                {"step": "repo_cloner", "error": str(e), "timestamp": datetime.utcnow().isoformat()}
            ],
            "pipeline_status": "failed",
            "current_step": "repo_cloner",
        }

    files = _collect_files(clone_dir)

    file_contents: dict[str, str] = {}
    total_secrets = 0
    for fpath in files:
        try:
            with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                raw = f.read()
            masked, n = _mask_secrets(raw)
            total_secrets += n
            rel = os.path.relpath(fpath, clone_dir)
            file_contents[rel] = masked
        except Exception:
            pass

    if total_secrets > 0:
        log.warning("secrets_masked", secrets_count=total_secrets)

    log.info(
        "repo_cloned",
        files_count=len(file_contents),
        clone_duration_ms=0,
        secrets_masked=total_secrets,
    )

    return {
        "cloned_path": clone_dir,
        "file_list": list(file_contents.keys()),
        "file_contents": file_contents,
        "current_step": "repo_cloner",
    }
