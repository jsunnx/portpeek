# -*- coding: utf-8 -*-
from __future__ import annotations

import argparse
import os
import sys
import time

from . import __version__
from .core import (
    PortEntry,
    entries_to_json,
    find_by_name,
    find_by_pid,
    find_port,
    kill_port,
    list_ports,
    next_free_port,
)


def _force_utf8_stdout() -> None:
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def _emit(text: str, force_utf8: bool = False) -> None:
    """Print text; when force_utf8 (JSON/machine output), write raw UTF-8 bytes.

    PowerShell `>` re-encodes text streams to UTF-16 — use --output for files,
    or cmd.exe redirection for portable bytes.
    """
    data = (text if text.endswith("\n") else text + "\n").encode("utf-8")
    if force_utf8:
        try:
            buf = getattr(sys.stdout, "buffer", None)
            if buf is not None:
                buf.write(data)
                buf.flush()
                return
        except Exception:
            pass
    # Human table: decode for text stdout
    try:
        sys.stdout.write(data.decode("utf-8", errors="replace"))
    except Exception:
        print(text)


def _use_color() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


_C = {"g": "", "y": "", "d": "", "r": "", "b": "", "e": ""}


def _enable_color() -> None:
    if not _use_color():
        return
    _C.update(
        {
            "g": "\033[32m",
            "y": "\033[33m",
            "d": "\033[90m",
            "r": "\033[31m",
            "b": "\033[36m",
            "e": "\033[0m",
        }
    )


def _pad(s: str, n: int) -> str:
    width = sum(2 if ord(ch) > 127 else 1 for ch in s)
    if width >= n:
        return s
    return s + " " * (n - width)


def _color_state(state: str) -> str:
    if state.upper() in {"LISTENING", "LISTEN"}:
        return f"{_C['g']}{state}{_C['e']}"
    return state


def _color_proto(proto: str) -> str:
    if proto.upper().startswith("UDP"):
        return f"{_C['y']}{proto}{_C['e']}"
    return f"{_C['b']}{proto}{_C['e']}"


def _color_process(name: str) -> str:
    low = name.lower()
    if any(k in low for k in ("node", "python", "java", "go", "deno", "bun")):
        return f"{_C['g']}{name}{_C['e']}"
    return name


def _print_table(entries: list[PortEntry]) -> None:
    if not entries:
        print("No ports found.")
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
            widths[i] = max(
                widths[i], min(32, sum(2 if ord(ch) > 127 else 1 for ch in cell))
            )

    def fmt_plain(row):
        return "  ".join(_pad(cell, widths[i]) for i, cell in enumerate(row))

    def fmt_color(row):
        parts = []
        for i, cell in enumerate(row):
            pad = _pad(cell, widths[i])
            # pad after visible color codes
            if i == 0:
                pad = _pad(cell, widths[i])
                parts.append(f"{_C['b']}{pad}{_C['e']}")
            elif i == 3:
                colored = _color_state(cell)
                pad_len = widths[i] - sum(2 if ord(ch) > 127 else 1 for ch in cell)
                parts.append(colored + " " * max(0, pad_len))
            elif i == 4:
                colored = _color_process(cell)
                pad_len = widths[i] - sum(2 if ord(ch) > 127 else 1 for ch in cell)
                parts.append(colored + " " * max(0, pad_len))
            else:
                parts.append(pad)
        return "  ".join(parts)

    print(fmt_plain(headers) if not _use_color() else fmt_color(headers))
    print(fmt_plain(tuple("-" * w for w in widths)))
    for row in rows:
        print(fmt_plain(row) if not _use_color() else fmt_color(row))
    print(f"\n{len(entries)} record(s)")


def _admin_hint(msg: str) -> str:
    low = msg.lower()
    if "denied" in low or "拒绝" in msg or "access" in low:
        return f"{msg} — try running as Administrator"
    return msg


def main(argv: list[str] | None = None) -> int:
    _force_utf8_stdout()
    _enable_color()
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
        "--pid",
        type=int,
        metavar="PID",
        help="show ports held by a process id",
    )
    parser.add_argument(
        "--name",
        metavar="SUBSTR",
        help="filter by process name substring, e.g. --name node",
    )
    parser.add_argument(
        "--free",
        nargs="?",
        type=int,
        const=3000,
        metavar="START",
        help="find a free TCP port starting from START (default 3000)",
    )
    parser.add_argument(
        "--watch",
        type=float,
        metavar="SEC",
        help="poll a port every SEC seconds until state changes",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="disable ANSI colors",
    )
    parser.add_argument(
        "-o",
        "--output",
        metavar="FILE",
        help="write JSON/text result to FILE as UTF-8 (avoids PowerShell redirect issues)",
    )
    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version=f"portpeek {__version__}",
    )
    args = parser.parse_args(argv)

    if args.no_color:
        _C.update({"g": "", "y": "", "d": "", "r": "", "b": "", "e": ""})

    def emit(text: str, machine: bool = False) -> None:
        if args.output:
            with open(args.output, "w", encoding="utf-8", newline="\n") as f:
                f.write(text if text.endswith("\n") else text + "\n")
            if not machine:
                print(f"Wrote {args.output}")
            return
        _emit(text, force_utf8=machine)

    listen_only = not args.all

    if args.free is not None:
        port = next_free_port(start=args.free, end=args.free + 5000)
        if port is None:
            print(f"No free port found in [{args.free}, {args.free + 5000}).")
            return 1
        emit(str(port), machine=args.json or bool(args.output))
        return 0

    if args.watch is not None:
        if args.port is None:
            print("--watch requires a port number", file=sys.stderr)
            return 2
        last = None
        print(f"Watching port {args.port} every {args.watch}s (Ctrl+C to stop)...")
        try:
            while True:
                hits = find_port(args.port, listen_only=True)
                snap = tuple(sorted((e.pid, e.process_name, e.local_addr) for e in hits))
                if snap != last:
                    if last is not None:
                        print(f"[{time.strftime('%H:%M:%S')}] state changed")
                    _print_table(hits)
                    last = snap
                time.sleep(max(0.2, args.watch))
        except KeyboardInterrupt:
            print("\nStopped.")
            return 0

    if args.kill:
        if args.port is None:
            print(
                "--kill requires a port number, e.g. portpeek 3000 --kill",
                file=sys.stderr,
            )
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
                print(f"  fail  {_admin_hint(msg)}")
        after = find_port(args.port, listen_only=True)
        if after and failed == 0:
            print("Terminate requested; if still listening, try --force")
            return 0
        if after:
            print(
                f"Port {args.port} is still listening. "
                f"Try: portpeek {args.port} --kill --force"
            )
            return 1
        print(f"Port {args.port} is free.")
        return 0

    if args.pid is not None:
        entries = find_by_pid(args.pid, listen_only=listen_only)
        if args.json or args.output:
            emit(entries_to_json(entries), machine=True)
            return 0 if entries else 1
        if not entries:
            print(f"PID {args.pid} holds no ports (in this view).")
            return 1
        print(f"PID {args.pid} holds:\n")
        _print_table(entries)
        return 0

    if args.name is not None:
        entries = find_by_name(args.name, listen_only=listen_only)
        if args.json or args.output:
            emit(entries_to_json(entries), machine=True)
            return 0 if entries else 1
        if not entries:
            print(f"No process matching '{args.name}'.")
            return 1
        print(f"Processes matching '{args.name}':\n")
        _print_table(entries)
        return 0

    if args.port is not None:
        entries = find_port(args.port, listen_only=listen_only)
        if args.json or args.output:
            emit(entries_to_json(entries), machine=True)
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
    if args.json or args.output:
        emit(entries_to_json(entries), machine=True)
        return 0
    title = "Listening ports" if listen_only else "All connections"
    print(f"{title} · {len(entries)}\n" if entries else "")
    _print_table(entries)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
