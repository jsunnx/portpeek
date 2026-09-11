# -*- coding: utf-8 -*-
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, asdict
from typing import Iterable


@dataclass
class PortEntry:
    proto: str
    local_addr: str
    port: int
    pid: int
    state: str
    process_name: str = ""
    exe_path: str = ""


_NETSTAT_LINE = re.compile(
    r"^(?P<proto>\S+)\s+"
    r"(?P<local>\S+)\s+"
    r"(?P<remote>\S+)\s+"
    r"(?P<state>\S+)\s+"
    r"(?P<pid>\d+)\s*$"
)


def _run_netstat() -> str:
    creationflags = 0x08000000 if sys.platform == "win32" else 0
    raw = subprocess.run(
        ["netstat", "-ano"],
        capture_output=True,
        creationflags=creationflags,
        check=False,
    )
    data = raw.stdout
    for enc in ("utf-8", "gbk", "cp936", "latin-1"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace")


def _parse_netstat() -> list[PortEntry]:
    text = _run_netstat()
    entries: list[PortEntry] = []
    for line in text.splitlines():
        line = line.strip()
        m = _NETSTAT_LINE.match(line)
        if not m:
            continue
        proto = m.group("proto").upper()
        local = m.group("local")
        state = m.group("state").upper()
        if ":" not in local:
            continue
        addr, _, port_s = local.rpartition(":")
        if not port_s.isdigit():
            continue
        entries.append(
            PortEntry(
                proto=proto,
                local_addr=addr,
                port=int(port_s),
                pid=int(m.group("pid")),
                state=state,
            )
        )
    return entries


def _process_map(pids: Iterable[int]) -> dict[int, tuple[str, str]]:
    info: dict[int, tuple[str, str]] = {}
    wanted = set(pids)
    if not wanted:
        return info
    if sys.platform == "win32":
        creationflags = 0x08000000
        cmd = (
            "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; "
            "$OutputEncoding=[System.Text.Encoding]::UTF8; "
            "Get-Process | Select-Object Id,ProcessName,Path | "
            "ConvertTo-Json -Compress"
        )
        completed = subprocess.run(
            ["powershell", "-NoProfile", "-Command", cmd],
            capture_output=True,
            creationflags=creationflags,
            check=False,
        )
        raw_bytes = completed.stdout
        raw = None
        for enc in ("utf-8-sig", "utf-8", "gbk", "cp936", "latin-1"):
            try:
                raw = raw_bytes.decode(enc).strip()
                break
            except UnicodeDecodeError:
                continue
        if raw is None:
            raw = raw_bytes.decode("utf-8", errors="replace").strip()
        if raw:
            try:
                data = json.loads(raw)
            except json.JSONDecodeError:
                data = None
            if isinstance(data, dict):
                data = [data]
            if isinstance(data, list):
                for item in data:
                    pid = int(item.get("Id") or 0)
                    name = str(item.get("ProcessName") or "")
                    path = str(item.get("Path") or "")
                    if pid:
                        info[pid] = (name, path)
        return info

    # POSIX fallback
    for pid in wanted:
        try:
            name = os.readlink(f"/proc/{pid}/exe")
        except OSError:
            name = ""
        info[pid] = (os.path.basename(name) if name else "", name)
    return info


def list_ports(
    listen_only: bool = True,
    include_pids: set[int] | None = None,
) -> list[PortEntry]:
    entries = _parse_netstat()
    if listen_only:
        entries = [e for e in entries if e.state in {"LISTENING", "LISTEN"}]
    if include_pids is not None:
        entries = [e for e in entries if e.pid in include_pids]

    pmap = _process_map(e.pid for e in entries)
    for e in entries:
        name, path = pmap.get(e.pid, ("", ""))
        e.process_name = name
        e.exe_path = path
    # 去重：同一 proto/port/pid 只留一条
    seen: set[tuple[str, int, int]] = set()
    uniq: list[PortEntry] = []
    for e in entries:
        key = (e.proto, e.port, e.pid)
        if key in seen:
            continue
        seen.add(key)
        uniq.append(e)
    uniq.sort(key=lambda x: (x.port, x.pid, x.proto))
    return uniq


def find_port(port: int, listen_only: bool = True) -> list[PortEntry]:
    return [e for e in list_ports(listen_only=listen_only) if e.port == port]


def kill_port(port: int, force: bool = False) -> list[tuple[PortEntry, bool, str]]:
    """Return list of (entry, ok, message)."""
    results: list[tuple[PortEntry, bool, str]] = []
    hits = find_port(port, listen_only=False)
    if not hits:
        return results
    pids = sorted({e.pid for e in hits if e.pid})
    for pid in pids:
        if sys.platform == "win32":
            if force:
                args = ["taskkill", "/F", "/PID", str(pid)]
            else:
                args = ["taskkill", "/PID", str(pid)]
            completed = subprocess.run(
                args,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                creationflags=0x08000000,
                check=False,
            )
            ok = completed.returncode == 0
            msg = (completed.stdout or completed.stderr or "").strip().splitlines()
            results.append(
                (
                    PortEntry(
                        proto="",
                        local_addr="",
                        port=port,
                        pid=pid,
                        state="",
                    ),
                    ok,
                    msg[0] if msg else ("ok" if ok else "failed"),
                )
            )
        else:
            completed = subprocess.run(
                ["kill", "-9" if force else "-15", str(pid)],
                capture_output=True,
                text=True,
                check=False,
            )
            ok = completed.returncode == 0
            results.append(
                (
                    PortEntry("", "", port, pid, ""),
                    ok,
                    (completed.stderr or "ok").strip(),
                )
            )
    return results


def entries_to_json(entries: list[PortEntry]) -> str:
    return json.dumps([asdict(e) for e in entries], ensure_ascii=False, indent=2)
