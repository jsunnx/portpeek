# -*- coding: utf-8 -*-
from __future__ import annotations

import argparse
import sys

from . import __version__
from .core import PortEntry, entries_to_json, find_port, kill_port, list_ports


def _pad(s: str, n: int) -> str:
    # 中文按 2 列宽估算，表格更好看
    width = sum(2 if ord(ch) > 127 else 1 for ch in s)
    if width >= n:
        return s
    return s + " " * (n - width)


def _print_table(entries: list[PortEntry]) -> None:
    if not entries:
        print("没有找到监听端口。")
        return
    headers = ("PROTO", "PORT", "PID", "STATE", "PROCESS", "PATH")
    rows = []
    for e in entries:
        rows.append(
            (
                e.proto,
                str(e.port),
                str(e.pid),
                e.state,
                e.process_name or "-",
                e.exe_path or "-",
            )
        )
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], min(48, sum(2 if ord(ch) > 127 else 1 for ch in cell)))
    # PATH 最长截断
    widths[5] = min(widths[5], 48)

    def fmt_row(row):
        cells = []
        for i, cell in enumerate(row):
            if i == 5 and len(cell) > 46:
                cell = "…" + cell[-45:]
            cells.append(_pad(cell, widths[i]))
        return "  ".join(cells)

    print(fmt_row(headers))
    print(fmt_row(tuple("-" * w for w in widths)))
    for row in rows:
        print(fmt_row(row))
    print(f"\n共 {len(entries)} 条监听记录")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="portpeek",
        description="快速查看端口被谁占用，可一键结束进程。",
    )
    parser.add_argument(
        "port",
        nargs="?",
        type=int,
        help="只查看某个端口，例如: portpeek 3000",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="显示全部连接，不只 LISTEN",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="以 JSON 输出",
    )
    parser.add_argument(
        "--kill",
        action="store_true",
        help="结束占用该端口的进程（配合端口号）",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="配合 --kill 使用 /F 强制结束",
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
            print("--kill 需要指定端口号，例如: portpeek 3000 --kill", file=sys.stderr)
            return 2
        before = find_port(args.port, listen_only=False)
        if not before:
            print(f"端口 {args.port} 没有找到占用进程。")
            return 1
        print(f"准备结束占用端口 {args.port} 的进程...")
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
        after = find_port(args.port, listen_only=False)
        if after and failed == 0:
            # 残留连接
            print("已发送结束请求；若仍占用，可加 --force")
            return 0
        if after:
            print("端口仍被占用。可试: portpeek {0} --kill --force".format(args.port))
            return 1
        print(f"端口 {args.port} 已释放。")
        return 0

    if args.port is not None:
        entries = find_port(args.port, listen_only=listen_only)
        if args.json:
            print(entries_to_json(entries))
            return 0 if entries else 1
        if not entries:
            print(f"端口 {args.port} 未被占用（或不是监听状态）。")
            return 1
        print(f"端口 {args.port} 被占用:\n")
        _print_table(entries)
        pids = sorted({e.pid for e in entries})
        print("\n若要释放: portpeek {0} --kill".format(args.port))
        print("查看进程命令提示: tasklist /PID {0}".format(",".join(str(p) for p in pids)))
        return 0

    entries = list_ports(listen_only=listen_only)
    if args.json:
        print(entries_to_json(entries))
        return 0
    title = "监听端口" if listen_only else "全部连接"
    print(f"{title} · {len(entries)} 条\n" if entries else "")
    _print_table(entries)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
