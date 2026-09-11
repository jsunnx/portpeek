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
    is_protected_process,
    kill_port,
    kill_ports,
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


def _color_process(name: str) -> str:
    low = name.lower()
    if any(k in low for k in ("node", "python", "java", "go", "deno", "bun")):
        return f"{_C['g']}{name}{_C['e']}"
    return name


def _sort_entries(entries: list[PortEntry], key: str) -> list[PortEntry]:
    if key == "pid":
        return sorted(entries, key=lambda e: (e.pid, e.port, e.proto, e.local_addr))
    if key == "name":
        return sorted(
            entries,
            key=lambda e: ((e.process_name or "").lower(), e.port, e.pid),
        )
    return sorted(entries, key=lambda e: (e.port, e.proto, e.local_addr, e.pid))


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
            if i == 0:
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
        if "administrator" in low:
            return msg
        return f"{msg} — try running as Administrator"
    return msg


def _do_kill(ports: list[int], force: bool, unsafe: bool) -> int:
    if not ports:
        print("--kill requires at least one port number", file=sys.stderr)
        return 2
    any_live = False
    for port in ports:
        before = find_port(port, listen_only=True)
        if not before:
            print(f"No listening process found on port {port}.")
            continue
        any_live = True
        print(f"Terminating listening process(es) on port {port}...")
        for e in before:
            name = e.process_name or "?"
            tag = " [protected]" if is_protected_process(e) else ""
            print(f"  PID {e.pid}  {name}{tag}")
        results = kill_port(port, force=force, unsafe=unsafe)
        killed = 0
        failed = 0
        skipped = 0
        for entry, ok, msg in results:
            if "protected process skipped" in msg:
                skipped += 1
                print(f"  skip  {msg}")
                continue
            if ok:
                killed += 1
                print(f"  ok  {msg}")
            else:
                failed += 1
                print(f"  fail  {_admin_hint(msg)}")
        after = find_port(port, listen_only=True)
        remaining_killable = [e for e in after if not is_protected_process(e)]
        if skipped and not remaining_killable and failed == 0:
            print(
                f"Port {port} still held by protected process(es). "
                f"Use --unsafe --kill only if you know what you are doing."
            )
        elif remaining_killable and killed == 0 and failed == 0 and not skipped:
            print("Terminate requested; if still listening, try --force")
        elif remaining_killable and (failed or killed):
            print(
                f"Port {port} is still listening. "
                f"Try: portpeek {port} --kill --force"
            )
        elif not after:
            print(f"Port {port} is free.")
        elif skipped and not remaining_killable:
            pass
        else:
            print(f"Port {port} is free.")

    if not any_live:
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    _force_utf8_stdout()
    _enable_color()
    parser = argparse.ArgumentParser(
        prog="portpeek",
        description="See who occupies a port, and free it in one command.",
    )
    parser.add_argument(
        "ports",
        nargs="*",
        type=int,
        metavar="PORT",
        help="one or more ports, e.g. portpeek 3000  3000 5173",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="show all connections, not only LISTEN",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="print JSON output (schema_version=1)",
    )
    parser.add_argument(
        "--kill",
        action="store_true",
        help="terminate listening holders (port numbers required)",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="with --kill, force terminate",
    )
    parser.add_argument(
        "--unsafe",
        action="store_true",
        help="with --kill, allow terminating protected OS processes (dangerous)",
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
        "--sort",
        choices=("port", "pid", "name"),
        default="port",
        help="sort table by port (default), pid, or name",
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
        help="write JSON/text result to FILE as UTF-8",
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
        if not args.ports:
            print("--watch requires a port number", file=sys.stderr)
            return 2
        watch_port = args.ports[0]
        last = None
        print(f"Watching port {watch_port} every {args.watch}s (Ctrl+C to stop)...")
        try:
            while True:
                hits = find_port(watch_port, listen_only=True)
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
        return _do_kill(args.ports, force=args.force, unsafe=args.unsafe)

    if args.pid is not None:
        entries = _sort_entries(find_by_pid(args.pid, listen_only=listen_only), args.sort)
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
        entries = _sort_entries(find_by_name(args.name, listen_only=listen_only), args.sort)
        if args.json or args.output:
            emit(entries_to_json(entries), machine=True)
            return 0 if entries else 1
        if not entries:
            print(f"No process matching '{args.name}'.")
            return 1
        print(f"Processes matching '{args.name}':\n")
        _print_table(entries)
        return 0

    if len(args.ports) == 1:
        entries = find_port(args.ports[0], listen_only=listen_only)
        entries = _sort_entries(entries, args.sort)
        if args.json or args.output:
            emit(entries_to_json(entries), machine=True)
            return 0 if entries else 1
        if not entries:
            print(f"Port {args.ports[0]} is not in use (or not listening).")
            return 1
        print(f"Port {args.ports[0]} is in use:\n")
        _print_table(entries)
        pids = sorted({e.pid for e in entries if e.pid})
        print(f"\nTo free it: portpeek {args.ports[0]} --kill")
        if sys.platform == "win32" and pids:
            print(f"Process list hint: tasklist /PID {','.join(str(p) for p in pids)}")
        return 0

    if len(args.ports) > 1:
        collected: list[PortEntry] = []
        for p in args.ports:
            collected.extend(find_port(p, listen_only=listen_only))
        collected = _sort_entries(collected, args.sort)
        if args.json or args.output:
            emit(entries_to_json(collected), machine=True)
            return 0 if collected else 1
        if not collected:
            print("None of the given ports are listening.")
            return 1
        print(f"{len(args.ports)} ports requested:\n")
        _print_table(collected)
        print("\nTo free: portpeek " + " ".join(str(p) for p in args.ports) + " --kill")
        return 0

    entries = _sort_entries(list_ports(listen_only=listen_only), args.sort)
    if args.json or args.output:
        emit(entries_to_json(entries), machine=True)
        return 0
    title = "Listening ports" if listen_only else "All connections"
    print(f"{title} · {len(entries)}\n" if entries else "")
    _print_table(entries)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
