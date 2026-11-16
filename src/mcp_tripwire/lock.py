"""The lock file (pinned tool fingerprints) and the comparison between pinned and live tools."""

from __future__ import annotations

import difflib
import hashlib
import json
import os
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

LOCK_VERSION = 1
DEFAULT_LOCK = Path(os.environ.get("MCP_TRIPWIRE_LOCK", Path.home() / ".mcp-tripwire" / "lock.json"))


def _sha(obj) -> str:
    raw = obj if isinstance(obj, str) else json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def fingerprint(tool: dict) -> dict:
    """What we pin per tool. The description text is kept so a change can be shown as a diff."""
    contract = {
        "inputSchema": tool.get("inputSchema") or {},
        "outputSchema": tool.get("outputSchema") or {},
        "annotations": tool.get("annotations") or {},
    }
    return {
        "description": tool.get("description") or "",
        "description_sha256": _sha(tool.get("description") or ""),
        "contract_sha256": _sha(contract),
        "contract": contract,
    }


def load(path: Path = DEFAULT_LOCK) -> dict:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {"version": LOCK_VERSION, "servers": {}}
    if not isinstance(data, dict) or "servers" not in data:
        raise ValueError(f"{path} is not an mcp-tripwire lock file")
    return data


def save(data: dict, path: Path = DEFAULT_LOCK) -> None:
    """Atomic write, so a crash never leaves a half-written lock file."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".lock-", suffix=".json")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True, ensure_ascii=False)
        f.write("\n")
    os.replace(tmp, path)


def pin_entry(name: str, target: str, source: str, tools: list[dict]) -> dict:
    return {
        "name": name,
        "target": target,
        "source": source,
        "pinned_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "tools": {t["name"]: fingerprint(t) for t in tools if t.get("name")},
    }


@dataclass
class Drift:
    added: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    description_changed: dict[str, str] = field(default_factory=dict)  # tool -> unified diff
    contract_changed: list[str] = field(default_factory=list)

    @property
    def changed(self) -> bool:
        return bool(self.added or self.removed or self.description_changed or self.contract_changed)

    def as_dict(self) -> dict:
        return {
            "added": self.added,
            "removed": self.removed,
            "description_changed": self.description_changed,
            "contract_changed": self.contract_changed,
        }


def compare(pinned_tools: dict, live_tools: list[dict]) -> Drift:
    live = {t["name"]: fingerprint(t) for t in live_tools if t.get("name")}
    d = Drift(added=sorted(set(live) - set(pinned_tools)), removed=sorted(set(pinned_tools) - set(live)))
    for name in sorted(set(live) & set(pinned_tools)):
        old, new = pinned_tools[name], live[name]
        if old.get("description_sha256") != new["description_sha256"]:
            diff = difflib.unified_diff(
                (old.get("description") or "").splitlines(),
                new["description"].splitlines(),
                fromfile=f"{name} (pinned)",
                tofile=f"{name} (now)",
                lineterm="",
                n=1,
            )
            d.description_changed[name] = "\n".join(diff)
        if old.get("contract_sha256") != new["contract_sha256"]:
            d.contract_changed.append(name)
    return d
