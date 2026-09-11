# -*- coding: utf-8 -*-
from __future__ import annotations

import argparse
import sys

from . import __version__
from .core import PortEntry, entries_to_json, find_port, kill_port, list_ports


def _force_utf8_stdout() -> None:
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def _pad(s: str, n: int) -> str:
    width = sum(2 if ord(ch) > 127 else 1 for ch in s)
    if width >= n:
        return s
    return s + " " * (n - width)


def _print_table(entries: list[PortEntry]) -> None:
    if not entries:
        print("No listening ports found.")
        return
    headers = ("PROTO", "PORT", "PID", "STATE", "PROCESS", "ADDRESS")
    rows = []
    for e in entries:
        rows.append(
            (
                e.proto,
                str(e.port),
                str(e.pid),
                e.state,
                e.process_name or "-",
                e.local_addr or "-",
            )
        )
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], min(32, sum(2 if ord(ch) > 127 else 1 for ch in cell)))

    def fmt_row(row):
        cells = [_pad(cell, widths[i]) for i, cell in enumerate(row)]
        return "  ".join(cells)

    print(fmt_row(headers))
    print(fmt_row(tuple("-" * w for w in widths)))
    for row in rows:
        print(fmt_row(row))
    print(f"\n{len(entries)} record(s)")


def main(argv: list[str] | None = None) -> int:
    _force_utf8_stdout()
    parser = argparse.ArgumentParser(
        prog="portpeek",
        description="See who occupies a port, and free it in one command.",
    )
    parser.add_argument(
        "port",
        nargs="?",
        type=int,
        help="inspect a single port, e.g. portpeek 3000",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="show all connections, not only LISTEN",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="print JSON output",
    )
    parser.add_argument(
        "--kill",
        action="store_true",
        help="terminate the process holding the port (requires a port number)",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="with --kill, force terminate",
    )
    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version=f"portpeek {__version__}",
    )
    args = parser.parse_args(argv)

    listen_only = not args.all

    if args.kill:
        if args.port is None:
            print("--kill requires a port number, e.g. portpeek 3000 --kill", file=sys.stderr)
            return 2
        before = find_port(args.port, listen_only=True)
        if not before:
            print(f"No listening process found on port {args.port}.")
            return 1
        print(f"Terminating listening process(es) on port {args.port}...")
        for e in before:
            name = e.process_name or "?"
            print(f"  PID {e.pid}  {name}")
        results = kill_port(args.port, force=args.force)
        failed = 0
        for _, ok, msg in results:
            if ok:
                print(f"  ok  {msg}")
            else:
                failed += 1
                print(f"  fail  {msg}")
        # TIME_WAIT / CLOSE_WAIT must not count as "still occupied"
        after = find_port(args.port, listen_only=True)
        if after and failed == 0:
            print("Terminate requested; if still listening, try --force")
            return 0
        if after:
            print(f"Port {args.port} is still listening. Try: portpeek {args.port} --kill --force")
            return 1
        print(f"Port {args.port} is free.")
        return 0

    if args.port is not None:
        entries = find_port(args.port, listen_only=listen_only)
        if args.json:
            print(entries_to_json(entries))
            return 0 if entries else 1
        if not entries:
            print(f"Port {args.port} is not in use (or not listening).")
            return 1
        print(f"Port {args.port} is in use:\n")
        _print_table(entries)
        pids = sorted({e.pid for e in entries if e.pid})
        print(f"\nTo free it: portpeek {args.port} --kill")
        if sys.platform == "win32" and pids:
            print(f"Process list hint: tasklist /PID {','.join(str(p) for p in pids)}")
        return 0

    entries = list_ports(listen_only=listen_only)
    if args.json:
        print(entries_to_json(entries))
        return 0
    title = "Listening ports" if listen_only else "All connections"
    print(f"{title} · {len(entries)}\n" if entries else "")
    _print_table(entries)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
