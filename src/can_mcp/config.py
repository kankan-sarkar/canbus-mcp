"""Sandbox paths, token limits, and backup settings for the can-mcp server."""
from __future__ import annotations

import os
from pathlib import Path


def get_workspace_root() -> Path:
    """Root directory all file I/O tools must stay within.

    Resolved fresh on every call (rather than cached at import time) so tests
    can point `CAN_MCP_WORKSPACE_ROOT` at a temp directory per-case.
    """
    root = os.environ.get("CAN_MCP_WORKSPACE_ROOT")
    base = Path(root) if root else Path.cwd()
    return base.resolve()


class WorkspaceSecurityError(Exception):
    """Raised when a tool is asked to touch a path outside the sandbox."""


def resolve_workspace_path(raw_path: str) -> Path:
    """Resolve `raw_path` and guarantee it stays inside the workspace root.

    Rejects absolute paths and `..` traversal that would escape the sandbox,
    per REQUIREMENTS.md section 2.2.3 (no path traversal).
    """
    root = get_workspace_root()
    candidate = (root / raw_path).resolve() if not Path(raw_path).is_absolute() else Path(raw_path).resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise WorkspaceSecurityError(
            f"Path '{raw_path}' resolves outside the allowed workspace root '{root}'."
        ) from exc
    return candidate


# Stage 4+ guardrail: tools must never return more than this many characters
# of payload to the LLM. Defined here now so later stages share one knob.
MAX_RESPONSE_CHARS = 16_000

BACKUP_SUFFIX = ".bak"
