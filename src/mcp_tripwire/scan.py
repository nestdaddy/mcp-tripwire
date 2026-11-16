"""Heuristic checks for prompt-injection patterns in what an MCP server tells the model.

Scans the tool description AND every description inside the input schema (attacks often hide in a parameter's
description). Heuristics, not proof: a finding means "a human should read this", not "this is malicious".

The rules were tuned against the tool descriptions of ~21,500 live public MCP servers (NestDaddy MCP directory,
2026-11): they look for an INSTRUCTION to do something harmful (read a credential file, hide an action from the
user, send private data to a URL), not for a mere mention of a file name or of the word "injection".
"""

from __future__ import annotations

import re
from dataclasses import dataclass

HIGH, MEDIUM, LOW = "high", "medium", "low"
_ORDER = {HIGH: 0, MEDIUM: 1, LOW: 2}


@dataclass
class Finding:
    tool: str
    where: str  # "description" or "param:<name>"
    rule: str
    severity: str
    message: str
    excerpt: str

    def as_dict(self) -> dict:
        return self.__dict__.copy()


# Bidi overrides and Unicode tag characters hide text from humans: high. Zero-width space, word joiners and BOM are
# often copy-paste debris: medium. ZWNJ/ZWJ (U+200C/D) and LRM/RLM (U+200E/F) are not flagged at all: Persian,
# Arabic, Indic scripts and emoji use them legitimately.
_HIDDEN_STRONG = re.compile("[‪-‮⁦-⁩\U000e0000-\U000e007f]")
_HIDDEN_WEAK = re.compile("[​⁠-⁤﻿]")

_SENSITIVE = (
    r"(~/\.ssh|\.ssh/|\bid_rsa\b|\bid_ed25519\b|\.aws/credentials|/etc/passwd|/etc/shadow|\.npmrc|\.pypirc|"
    r"\.netrc|claude_desktop_config\.json|\.cursor/mcp\.json|(?<![\w.])\.env\b(?!\.)|private[ _]keys?|"
    r"seed phrase|mnemonic)"
)
_READ_VERB = r"\b(read|cat|open|load|include|attach|send|upload|pass|copy|paste|forward|extract|collect)\b"
_PRIVATE = (
    r"(conversation|chat history|previous messages|system prompt|secrets?|api[ _-]?keys?|tokens?|credentials|"
    r"passwords?|environment variables|env vars|file contents?|private|ssh)"
)
_NEGATED = re.compile(r"\b(never|not|don't|do not|no|without|won't|cannot|can't)\b[^.\n]{0,20}$", re.I)
_NEGATION_WORD = re.compile(r"\b(no|never|not|without)\b", re.I)
_DETECTOR_CONTEXT = re.compile(
    r"(injection|jailbreak|detect|scan|firewall|block|guard|redact|leak|mask|shadowing|poison)", re.I
)
_AUTH_USAGE = re.compile(r"\b(header|authorization|bearer)\b", re.I)
_QUOTES = ('"', "'", "“", "‘", "(", "`")

RULES: list[tuple[str, str, re.Pattern, str]] = [
    (
        "ignore-instructions",
        HIGH,
        re.compile(
            r"\b(ignore|disregard|forget)\b[^.\n]{0,30}\b(all |any )?(previous|prior|above|earlier|system|other)\b"
            r"[^.\n]{0,20}\b(instructions?|rules|prompts?|guidelines)\b",
            re.I,
        ),
        "asks the model to ignore its other instructions",
    ),
    (
        "hide-from-user",
        HIGH,
        re.compile(
            r"\b(do not|don't|never|without)\s+(tell|telling|inform|informing|mention|mentioning|notify|notifying|"
            r"alert|alerting)\s+(the\s+)?user\s+(about|that)\b|\b(do not|don't|never)\s+(mention|reveal|disclose)\s+"
            r"(this|that|it)\b(?!\s+(key|secret|token|password))",
            re.I,
        ),
        "asks the model to hide something from the user",
    ),
    (
        "read-sensitive-file",
        HIGH,
        re.compile(_READ_VERB + r"[^.\n]{0,40}" + _SENSITIVE, re.I),
        "asks the model to read or send a credential or config file",
    ),
    (
        "exfiltration",
        HIGH,
        re.compile(
            r"\b(send|post|upload|forward|transmit|exfiltrate|include|append)\b[^.\n]{0,50}"
            + _PRIVATE
            + r"[^.\n]{0,60}https?://",
            re.I,
        ),
        "tells the model to send private data to a URL",
    ),
    (
        "fake-system-tag",
        MEDIUM,
        re.compile(
            r"(?<![\w>])<\s*/?\s*(important|system|instructions?|secret|admin|critical|hidden)\s*>(?![\w<])", re.I
        ),
        "uses tags that try to look like system instructions",
    ),
    (
        "tool-shadowing",
        LOW,
        re.compile(
            r"\b(before|instead of|whenever|every time)\b[^.\n]{0,40}\b(using|calling|call|use)\b[^.\n]{0,20}\b"
            r"(any|every|all)\s+(other\s+)?tools?\b",
            re.I,
        ),
        "tries to change how the model uses all other tools",
    ),
    ("base64-blob", MEDIUM, re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{160,}={0,2}"), "contains a long encoded blob"),
]

LONG_DESCRIPTION = 4000


def _excerpt(text: str, m: re.Match | None, width: int = 90) -> str:
    if not m:
        return text[:width].replace("\n", " ")
    start = max(0, m.start() - 20)
    return text[start : start + width].replace("\n", " ")


def _texts(tool: dict):
    yield "description", tool.get("description") or ""
    props = (tool.get("inputSchema") or {}).get("properties") or {}
    if isinstance(props, dict):
        for pname, pschema in props.items():
            if isinstance(pschema, dict):
                yield f"param:{pname}", str(pschema.get("description") or "") + " " + str(pschema.get("title") or "")


def _is_benign(rule: str, text: str, m: re.Match, tool_name: str = "") -> bool:
    before = text[max(0, m.start() - 40) : m.start()]
    around = tool_name.replace("_", " ") + " " + text[max(0, m.start() - 200) : m.end() + 80]
    if rule in ("read-sensitive-file", "exfiltration", "ignore-instructions"):
        if _NEGATED.search(before) or _NEGATION_WORD.search(m.group()):
            return True  # "never send your API key to ...", "Read-only, no private keys required"
    if rule in ("ignore-instructions", "read-sensitive-file", "fake-system-tag") and _DETECTOR_CONTEXT.search(around):
        return True  # a scanner or detector describing what it looks for
    if rule == "ignore-instructions" and before.rstrip()[-1:] in _QUOTES:
        return True  # a quoted example
    if rule == "exfiltration" and _AUTH_USAGE.search(m.group()):
        return True  # "send it as an Authorization: Bearer header to https://..." (how to use a key)
    return False


def scan_tool(tool: dict) -> list[Finding]:
    name = tool.get("name", "?")
    out: list[Finding] = []
    for where, text in _texts(tool):
        if not text.strip():
            continue
        for pattern, severity in ((_HIDDEN_STRONG, HIGH), (_HIDDEN_WEAK, MEDIUM)):
            hidden = pattern.search(text)
            if hidden:
                out.append(
                    Finding(
                        name,
                        where,
                        "hidden-unicode",
                        severity,
                        f"contains invisible Unicode characters (U+{ord(hidden.group()):04X})",
                        _excerpt(text, hidden),
                    )
                )
                break
        for rule, severity, pattern, message in RULES:
            for m in pattern.finditer(text):
                if not _is_benign(rule, text, m, name):
                    out.append(Finding(name, where, rule, severity, message, _excerpt(text, m)))
                    break
    desc = tool.get("description") or ""
    if len(desc) > LONG_DESCRIPTION:
        out.append(
            Finding(
                name,
                "description",
                "very-long",
                LOW,
                f"description is {len(desc):,} characters (room for hidden instructions)",
                desc[:90],
            )
        )
    return out


def scan_tools(tools: list[dict]) -> list[Finding]:
    findings = [f for t in tools for f in scan_tool(t)]
    return sorted(findings, key=lambda f: (_ORDER[f.severity], f.tool, f.rule))
