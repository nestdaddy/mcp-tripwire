"""Find the MCP servers configured in the AI clients on this machine (and in the current project).

Supported: Claude Desktop, Claude Code (user and project), Cursor (user and project), VS Code (project),
Windsurf. Every server becomes a `ServerSpec`. Secrets (header values, env values) are kept in memory only to
connect; they are never written to the lock file or printed.
"""

from __future__ import annotations

import json
import os
import platform
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


@dataclass
class ServerSpec:
    name: str
    transport: str  # "http" or "stdio" (or "memory" in tests)
    source: str  # which client/config file it came from
    url: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    command: str | None = None
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    obj: Any = None  # in-memory server (tests)

    @property
    def key(self) -> str:
        """Stable identity for the lock file: name + where it points (never secrets)."""
        if self.transport == "http":
            return f"{self.name}@{safe_url(self.url or '')}"
        if self.transport == "stdio":
            return f"{self.name}@stdio:{self.command or ''} {' '.join(self.args)}".strip()
        return f"{self.name}@{self.transport}"

    @property
    def target(self) -> str:
        if self.transport == "http":
            return safe_url(self.url or "")
        if self.transport == "stdio":
            return f"{self.command or ''} {' '.join(self.args)}".strip()
        return self.transport


_SECRET_PARAM = re.compile(r"(key|token|secret|auth|password|sig|signature|session|code)", re.I)


def safe_url(url: str) -> str:
    """Drop credentials and secret-looking query values from a URL before storing or printing it."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return url
    netloc = parts.hostname or ""
    if parts.port:
        netloc += f":{parts.port}"
    query = urlencode(
        [(k, "***" if _SECRET_PARAM.search(k) else v) for k, v in parse_qsl(parts.query, keep_blank_values=True)]
    )
    return urlunsplit((parts.scheme, netloc, parts.path, query, ""))


_ENV_REF = re.compile(r"\$\{(?:env:)?([A-Za-z_][A-Za-z0-9_]*)\}")


def expand(value: Any) -> Any:
    """Expand ${VAR} and ${env:VAR} (used by Cursor, VS Code and Claude Code configs)."""
    if isinstance(value, str):
        return _ENV_REF.sub(lambda m: os.environ.get(m.group(1), ""), value)
    if isinstance(value, dict):
        return {k: expand(v) for k, v in value.items()}
    if isinstance(value, list):
        return [expand(v) for v in value]
    return value


def _read_json(path: Path) -> Any:
    try:
        text = path.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeDecodeError):
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        # VS Code and some editors allow comments and trailing commas
        text = re.sub(r"(?m)^\s*//.*$", "", text)
        text = re.sub(r",(\s*[}\]])", r"\1", text)
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return None


def spec_from_entry(name: str, entry: dict, source: str) -> ServerSpec | None:
    """One config entry -> ServerSpec. Handles the field names of all supported clients."""
    if not isinstance(entry, dict) or entry.get("disabled") is True:
        return None
    entry = expand(entry)
    url = entry.get("url") or entry.get("serverUrl") or entry.get("httpUrl")
    kind = (entry.get("type") or entry.get("transport") or "").lower()
    if url and kind not in ("stdio",):
        headers = {str(k): str(v) for k, v in (entry.get("headers") or {}).items()}
        return ServerSpec(name=name, transport="http", source=source, url=str(url), headers=headers)
    if entry.get("command"):
        return ServerSpec(
            name=name,
            transport="stdio",
            source=source,
            command=str(entry["command"]),
            args=[str(a) for a in entry.get("args") or []],
            env={str(k): str(v) for k, v in (entry.get("env") or {}).items()},
        )
    return None


def _servers_in(data: Any, keys: tuple[str, ...]) -> dict:
    if not isinstance(data, dict):
        return {}
    for k in keys:
        if isinstance(data.get(k), dict):
            return data[k]
    return {}


def candidate_files(cwd: Path | None = None) -> list[tuple[str, Path, tuple[str, ...]]]:
    """(client label, path, keys that hold the server map) for every known config location."""
    home = Path.home()
    cwd = cwd or Path.cwd()
    system = platform.system()
    if system == "Darwin":
        claude_desktop = home / "Library/Application Support/Claude/claude_desktop_config.json"
    elif system == "Windows":
        claude_desktop = Path(os.environ.get("APPDATA", home / "AppData/Roaming")) / "Claude/claude_desktop_config.json"
    else:
        claude_desktop = home / ".config/Claude/claude_desktop_config.json"
    mcp = ("mcpServers",)
    return [
        ("Claude Desktop", claude_desktop, mcp),
        ("Claude Code (user)", home / ".claude.json", mcp),
        ("Claude Code (project)", cwd / ".mcp.json", mcp),
        ("Cursor (user)", home / ".cursor/mcp.json", mcp),
        ("Cursor (project)", cwd / ".cursor/mcp.json", mcp),
        ("VS Code (project)", cwd / ".vscode/mcp.json", ("servers", "mcpServers")),
        ("Windsurf", home / ".codeium/windsurf/mcp_config.json", mcp),
    ]


def discover(cwd: Path | None = None, extra_files: list[Path] | None = None) -> list[ServerSpec]:
    """All servers from known client configs plus any extra config files. Duplicates (same key) are merged."""
    found: dict[str, ServerSpec] = {}
    files = candidate_files(cwd)
    for path in extra_files or []:
        files.append((str(path), Path(path), ("mcpServers", "servers")))
    cwd_resolved = str((cwd or Path.cwd()).resolve())
    for label, path, keys in files:
        if not path.is_file():
            continue
        data = _read_json(path)
        servers = dict(_servers_in(data, keys))
        # Claude Code also keeps per-project servers inside ~/.claude.json
        if label == "Claude Code (user)" and isinstance(data, dict):
            proj = (data.get("projects") or {}).get(cwd_resolved) or {}
            servers.update(_servers_in(proj, ("mcpServers",)))
        for name, entry in servers.items():
            spec = spec_from_entry(str(name), entry, f"{label}: {path}")
            if spec and spec.key not in found:
                found[spec.key] = spec
    return list(found.values())
