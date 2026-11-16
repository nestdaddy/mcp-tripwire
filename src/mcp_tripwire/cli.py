"""mcp-tripwire command line.

  mcp-tripwire list                 servers found in your AI clients' configs
  mcp-tripwire pin                  record what every server's tools say today
  mcp-tripwire check                compare with the pinned version (exit 1 on any change)
  mcp-tripwire scan                 look for prompt-injection patterns in tool descriptions

Exit codes: 0 = clean, 1 = changes or high-severity findings, 2 = nothing could be checked (errors only).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path
from urllib.parse import urlsplit

from . import __version__
from .configs import ServerSpec, discover
from .fetch import FetchError, fetch_many
from .lock import DEFAULT_LOCK, compare, load, pin_entry, save
from .scan import HIGH, MEDIUM, scan_tools

USE_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")


def c(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m" if USE_COLOR else text


def red(t):
    return c(t, "31")


def green(t):
    return c(t, "32")


def yellow(t):
    return c(t, "33")


def dim(t):
    return c(t, "2")


def bold(t):
    return c(t, "1")


def _servers(args) -> tuple[list[ServerSpec], list[ServerSpec]]:
    """(servers to contact, stdio servers skipped because --stdio was not given)."""
    if args.url:
        headers = {}
        for h in args.header or []:
            if ":" not in h:
                raise SystemExit(f"--header must look like 'Name: value', got {h!r}")
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()
        specs = [
            ServerSpec(name=urlsplit(u).hostname or u, transport="http", source="command line", url=u, headers=headers)
            for u in args.url
        ]
    else:
        specs = discover(extra_files=[Path(p) for p in args.config or []])
    if args.only:
        wanted = {n.lower() for n in args.only}
        specs = [s for s in specs if s.name.lower() in wanted]
    skipped = [s for s in specs if s.transport == "stdio" and not args.stdio]
    return [s for s in specs if s not in skipped], skipped


def _fetch(specs, args):
    if not specs:
        return {}
    return asyncio.run(fetch_many(specs, timeout=args.timeout))


def _print_skipped(skipped, args):
    if skipped and not args.json:
        print(
            dim(
                f"Skipped {len(skipped)} local (stdio) server(s): checking them starts their command. "
                "Add --stdio to include them."
            )
        )


def cmd_list(args) -> int:
    specs, skipped = _servers(args)
    rows = [
        {"name": s.name, "transport": s.transport, "target": s.target, "source": s.source, "checked": s not in skipped}
        for s in specs + skipped
    ]
    if args.json:
        print(json.dumps(rows, indent=2))
        return 0
    if not rows:
        print("No MCP servers found. Use --url, or --config path/to/mcp.json.")
        return 0
    for r in rows:
        tag = "" if r["checked"] else dim("  (stdio, needs --stdio)")
        print(f"{bold(r['name'])}  {r['transport']}  {r['target']}{tag}\n  {dim(r['source'])}")
    return 0


def cmd_pin(args) -> int:
    specs, skipped = _servers(args)
    results = _fetch(specs, args)
    data = load(args.lock)
    pinned, errors = 0, 0
    report = []
    for s in specs:
        res = results.get(s.key)
        if isinstance(res, FetchError):
            errors += 1
            report.append({"server": s.name, "error": str(res)})
            if not args.json:
                print(f"{red('[ERROR]')} {s.name}: {res}")
            continue
        data["servers"][s.key] = pin_entry(s.name, s.target, s.source, res)
        pinned += 1
        report.append({"server": s.name, "tools": len(res)})
        if not args.json:
            print(f"{green('[PINNED]')} {s.name}: {len(res)} tools")
    if pinned:
        save(data, args.lock)
    if args.json:
        print(json.dumps({"lock": str(args.lock), "servers": report}, indent=2))
    else:
        _print_skipped(skipped, args)
        print(dim(f"Lock file: {args.lock}"))
    return 2 if errors and not pinned else 0


def cmd_check(args) -> int:
    specs, skipped = _servers(args)
    data = load(args.lock)
    results = _fetch(specs, args)
    drifted, checked, report = 0, 0, []
    for s in specs:
        res = results.get(s.key)
        entry = data["servers"].get(s.key)
        if isinstance(res, FetchError):
            report.append({"server": s.name, "status": "error", "error": str(res)})
            if not args.json:
                print(f"{red('[ERROR]')} {s.name}: {res}")
            continue
        if not entry:
            report.append({"server": s.name, "status": "not_pinned", "tools": len(res)})
            if not args.json:
                print(f"{yellow('[NEW]')} {s.name}: not pinned yet ({len(res)} tools). Run: mcp-tripwire pin")
            continue
        checked += 1
        d = compare(entry["tools"], res)
        status = "changed" if d.changed else "ok"
        drifted += d.changed
        report.append({"server": s.name, "status": status, "pinned_at": entry.get("pinned_at"), **d.as_dict()})
        if args.json:
            continue
        if not d.changed:
            print(f"{green('[OK]')} {s.name}: {len(res)} tools unchanged since {entry.get('pinned_at', '?')}")
            continue
        print(f"{red('[CHANGED]')} {bold(s.name)} (pinned {entry.get('pinned_at', '?')})")
        for t in d.added:
            print(f"  {yellow('+ new tool:')} {t}")
        for t in d.removed:
            print(f"  {yellow('- removed tool:')} {t}")
        for t, diff in d.description_changed.items():
            print(f"  {red('~ description changed:')} {t}")
            for line in diff.splitlines()[2:]:
                col = green if line.startswith("+") else red if line.startswith("-") else dim
                print("      " + col(line))
        for t in d.contract_changed:
            if t not in d.description_changed:
                print(f"  {yellow('~ arguments or annotations changed:')} {t}")
    if args.json:
        print(json.dumps({"lock": str(args.lock), "servers": report}, indent=2))
    else:
        _print_skipped(skipped, args)
        if drifted:
            print(
                f"\n{red(str(drifted))} server(s) changed. Review the new text; if you trust it, run: mcp-tripwire pin"
            )
    if drifted:
        return 1
    return 2 if specs and not checked and all(r["status"] == "error" for r in report) else 0


def cmd_scan(args) -> int:
    specs, skipped = _servers(args)
    results = _fetch(specs, args)
    fail_on = {HIGH} if args.fail_on == "high" else {HIGH, MEDIUM}
    worst_hit, report, errors = False, [], 0
    for s in specs:
        res = results.get(s.key)
        if isinstance(res, FetchError):
            errors += 1
            report.append({"server": s.name, "error": str(res)})
            if not args.json:
                print(f"{red('[ERROR]')} {s.name}: {res}")
            continue
        findings = scan_tools(res)
        worst_hit |= any(f.severity in fail_on for f in findings)
        report.append({"server": s.name, "tools": len(res), "findings": [f.as_dict() for f in findings]})
        if args.json:
            continue
        if not findings:
            print(f"{green('[CLEAN]')} {s.name}: {len(res)} tools, no suspicious patterns")
            continue
        print(f"{yellow('[REVIEW]')} {bold(s.name)}: {len(findings)} finding(s)")
        for f in findings:
            sev = (
                red(f.severity.upper())
                if f.severity == HIGH
                else yellow(f.severity.upper())
                if f.severity == MEDIUM
                else dim(f.severity.upper())
            )
            print(f"  {sev} {f.tool} ({f.where}): {f.message}\n      {dim(repr(f.excerpt))}")
    if args.json:
        print(json.dumps({"servers": report}, indent=2))
    else:
        _print_skipped(skipped, args)
    if worst_hit:
        return 1
    return 2 if specs and errors == len(specs) else 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="mcp-tripwire",
        description=__doc__.split("\n\n")[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split("\n\n", 1)[1],
    )
    p.add_argument("--version", action="version", version=f"mcp-tripwire {__version__}")
    sub = p.add_subparsers(dest="command", required=True)
    for name, fn, help_ in (
        ("list", cmd_list, "show the MCP servers found in your configs"),
        ("pin", cmd_pin, "record the current tool descriptions"),
        ("check", cmd_check, "compare live tools with the pinned ones"),
        ("scan", cmd_scan, "look for prompt-injection patterns"),
    ):
        sp = sub.add_parser(name, help=help_)
        sp.set_defaults(func=fn)
        sp.add_argument(
            "--url", action="append", help="check this remote MCP server URL instead of your configs (repeatable)"
        )
        sp.add_argument(
            "--header", action="append", help="HTTP header for --url servers, e.g. 'Authorization: Bearer KEY'"
        )
        sp.add_argument("--config", action="append", help="also read this MCP config file (repeatable)")
        sp.add_argument("--only", action="append", help="only this server name (repeatable)")
        sp.add_argument("--stdio", action="store_true", help="also start local (stdio) servers to read their tools")
        sp.add_argument("--lock", type=Path, default=DEFAULT_LOCK, help=f"lock file (default {DEFAULT_LOCK})")
        sp.add_argument("--timeout", type=float, default=30.0, help="seconds per server (default 30)")
        sp.add_argument("--json", action="store_true", help="machine-readable output")
        if name == "scan":
            sp.add_argument(
                "--fail-on",
                choices=["high", "medium"],
                default="high",
                help="exit 1 when a finding of this severity or worse is found (default high)",
            )
    return p


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(errors="replace")
        except (ValueError, OSError):
            pass
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except ValueError as exc:
        print(red(f"error: {exc}"), file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
