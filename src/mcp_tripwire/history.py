"""Public change history of remote MCP servers, from the NestDaddy MCP directory (checks every public remote
MCP server daily). Only the server's scheme, host and path are sent: never keys, headers or query strings."""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from urllib.parse import urlencode, urlsplit, urlunsplit

from . import __version__

DIRECTORY = os.environ.get("MCP_TRIPWIRE_DIRECTORY", "https://nestdaddy.com")
UA = f"mcp-tripwire/{__version__} (+https://github.com/nestdaddy/mcp-tripwire)"


class HistoryError(Exception):
    pass


def bare_url(url: str) -> str:
    """scheme://host/path only: no credentials, port-safe, no query or fragment."""
    p = urlsplit(url)
    host = p.hostname or ""
    if p.port:
        host += f":{p.port}"
    return urlunsplit((p.scheme or "https", host, p.path, "", ""))


def lookup(url: str, timeout: float = 15.0) -> dict | None:
    """History for a remote server URL, or None when the directory does not list it."""
    q = urlencode({"url": bare_url(url)})
    req = urllib.request.Request(
        f"{DIRECTORY}/mcp/servers/lookup.json?{q}", headers={"User-Agent": UA, "Accept": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise HistoryError(f"directory answered HTTP {e.code}") from None
    except (urllib.error.URLError, TimeoutError, ValueError) as e:
        raise HistoryError(f"directory unreachable: {type(e).__name__}") from None
