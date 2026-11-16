"""Connect to one MCP server and read its tool list (tools/list, all pages). Read-only: no tool is ever called."""

from __future__ import annotations

import asyncio
import os
from typing import Any

from mcp import ClientSession, StdioServerParameters, types
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import create_mcp_http_client, streamable_http_client

from .configs import ServerSpec

MAX_PAGES = 50


class FetchError(Exception):
    """A server could not be reached or did not answer tools/list. The message never contains secrets."""


def normalize_tool(tool: Any) -> dict:
    """Keep what the agent is told about a tool: name, description, input/output schema, annotations."""
    data = tool.model_dump(mode="json", by_alias=True, exclude_none=True) if hasattr(tool, "model_dump") else dict(tool)
    return {
        "name": data.get("name", ""),
        "description": data.get("description") or "",
        "inputSchema": data.get("inputSchema") or {},
        "outputSchema": data.get("outputSchema") or {},
        "annotations": data.get("annotations") or {},
    }


async def _list_all(session: ClientSession) -> list[dict]:
    tools: list[dict] = []
    cursor = None
    for _ in range(MAX_PAGES):
        params = types.PaginatedRequestParams(cursor=cursor) if cursor else None
        res = await session.list_tools(params=params)
        tools.extend(normalize_tool(t) for t in res.tools)
        cursor = getattr(res, "next_cursor", None) or getattr(res, "nextCursor", None)
        if not cursor:
            break
    return tools


async def _fetch(spec: ServerSpec) -> list[dict]:
    if spec.transport == "memory":
        from mcp.client.client import Client

        async with Client(spec.obj) as client:
            tools, cursor = [], None
            for _ in range(MAX_PAGES):
                res = await client.list_tools(cursor=cursor)
                tools.extend(normalize_tool(t) for t in res.tools)
                cursor = getattr(res, "next_cursor", None)
                if not cursor:
                    break
            return tools
    if spec.transport == "http":
        http_client = create_mcp_http_client(headers=spec.headers or None)
        async with http_client:
            async with streamable_http_client(spec.url, http_client=http_client) as streams:
                async with ClientSession(streams[0], streams[1]) as session:
                    await session.initialize()
                    return await _list_all(session)
    if spec.transport == "stdio":
        params = StdioServerParameters(command=spec.command, args=spec.args, env={**os.environ, **spec.env})
        async with stdio_client(params) as streams:
            async with ClientSession(streams[0], streams[1]) as session:
                await session.initialize()
                return await _list_all(session)
    raise FetchError(f"unsupported transport: {spec.transport}")


def _clean_error(exc: BaseException) -> str:
    """Short, secret-free description of a connection error (ExceptionGroups are unwrapped)."""
    # Works on Python 3.10 too (no built-in BaseExceptionGroup there; anyio uses the backport)
    while getattr(exc, "exceptions", None):
        exc = exc.exceptions[0]
    text = f"{type(exc).__name__}: {exc}".splitlines()[0]
    return text[:200]


async def fetch_tools(spec: ServerSpec, timeout: float = 30.0) -> list[dict]:
    try:
        return await asyncio.wait_for(_fetch(spec), timeout=timeout)
    except asyncio.TimeoutError:
        raise FetchError(f"no answer within {timeout:.0f} s") from None
    except FetchError:
        raise
    except BaseException as exc:  # noqa: BLE001 - transports raise many kinds of errors, incl. ExceptionGroup
        if isinstance(exc, (KeyboardInterrupt, SystemExit)):
            raise
        raise FetchError(_clean_error(exc)) from None


async def fetch_many(
    specs: list[ServerSpec], timeout: float = 30.0, concurrency: int = 6
) -> dict[str, list[dict] | FetchError]:
    """Fetch several servers in parallel; one failure never stops the others."""
    sem = asyncio.Semaphore(concurrency)
    out: dict[str, list[dict] | FetchError] = {}

    async def one(spec: ServerSpec) -> None:
        async with sem:
            try:
                out[spec.key] = await fetch_tools(spec, timeout)
            except FetchError as exc:
                out[spec.key] = exc

    await asyncio.gather(*(one(s) for s in specs))
    return out
