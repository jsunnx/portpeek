# -*- coding: utf-8 -*-
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass, asdict
from typing import Iterable


class ToolMissing(RuntimeError):
    """Raised when netstat/ss/lsof/powershell is not on PATH."""


@dataclass
class PortEntry:
    proto: str
    local_addr: str
    port: int
    pid: int
    state: str
    process_name: str = ""
    exe_path: str = ""


# Windows TCP: Proto Local Foreign State PID
_WIN_TCP = re.compile(
    r"^(?P<proto>TCP(?:v6)?)\s+"
    r"(?P<local>\S+)\s+"
    r"(?P<remote>\S+)\s+"
    r"(?P<state>\S+)\s+"
    r"(?P<pid>\d+)\s*$",
    re.IGNORECASE,
)

# Windows UDP: Proto Local Foreign PID  (no State column)
_WIN_UDP = re.compile(
    r"^(?P<proto>UDP(?:v6)?)\s+"
    r"(?P<local>\S+)\s+"
    r"(?P<remote>\S+)\s+"
    r"(?P<pid>\d+)\s*$",
    re.IGNORECASE,
)

# Linux ss: netid state recvq sendq local peer [users:(("name",pid=N,...))]
_SS_LINE = re.compile(
    r"^(?P<netid>tcp|udp|tcp6|udp6)\s+"
    r"(?P<state>\S+)\s+"
    r"(?P<recvq>\d+)\s+"
    r"(?P<sendq>\d+)\s+"
    r"(?P<local>\S+)\s+"
    r"(?P<peer>\S+)"
    r"(?:\s+users:\(\((?P<users>.+)\)\))?\s*$",
    re.IGNORECASE,
)

_SS_USER_PID = re.compile(r"pid=(\d+)")
# After _SS_LINE strips users:(( ... )), body looks like: "name",pid=456,fd=6
_SS_USER_NAME = re.compile(r'"([^"]+)"')

_SNAPSHOT_TTL = 0.8
_snapshot: tuple[float, list[PortEntry]] | None = None


def _decode(data: bytes) -> str:
    for enc in ("utf-8-sig", "utf-8", "gbk", "cp936", "latin-1"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace")


def _hidden_run(cmd: list[str], timeout: float | None = 15.0) -> tuple[int, str]:
    creationflags = 0x08000000 if sys.platform == "win32" else 0
    try:
        raw = subprocess.run(
            cmd,
            capture_output=True,
            creationflags=creationflags,
            check=False,
            timeout=timeout,
        )
    except FileNotFoundError as e:
        raise ToolMissing(
            f"Required tool '{cmd[0]}' was not found on PATH. "
            f"Install it or use a supported OS."
        ) from e
    except subprocess.TimeoutExpired as e:
        raise ToolMissing(f"'{' '.join(cmd)}' timed out after {timeout}s") from e
    return raw.returncode, _decode(raw.stdout)


def _split_host_port(addr: str) -> tuple[str, int] | None:
    if not addr or addr == "*:*":
        return None
    if addr.startswith("["):
        close = addr.find("]")
        if close < 0 or close + 1 >= len(addr) or addr[close + 1] != ":":
            return None
        host = addr[: close + 1]
        port_s = addr[close + 2 :]
    else:
        host, _, port_s = addr.rpartition(":")
    if not port_s.isdigit():
        return None
    return host, int(port_s)


def _parse_windows_netstat() -> list[PortEntry]:
    _, text = _hidden_run(["netstat", "-ano"])
    entries: list[PortEntry] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        mt = _WIN_TCP.match(line)
        if mt:
            hp = _split_host_port(mt.group("local"))
            if not hp:
                continue
            host, port = hp
            entries.append(
                PortEntry(
                    proto=mt.group("proto").upper(),
                    local_addr=host,
                    port=port,
                    pid=int(mt.group("pid")),
                    state=mt.group("state").upper(),
                )
            )
            continue
        mu = _WIN_UDP.match(line)
        if mu:
            hp = _split_host_port(mu.group("local"))
            if not hp:
                continue
            host, port = hp
            entries.append(
                PortEntry(
                    proto=mu.group("proto").upper(),
                    local_addr=host,
                    port=port,
                    pid=int(mu.group("pid")),
                    state="LISTENING",
                )
            )
    return entries


def _parse_linux_ss() -> list[PortEntry]:
    _, text = _hidden_run(["ss", "-tulnp"])
    entries: list[PortEntry] = []
    for line in text.splitlines():
        line = line.strip()
        m = _SS_LINE.match(line)
        if not m:
            continue
        netid = m.group("netid").upper()
        state = m.group("state").upper()
        if netid.startswith("TCP") and state not in {"LISTEN", "LISTENING"}:
            continue
        if netid.startswith("UDP") and state not in {
            "UNCONN",
            "UNCONNECTED",
            "LISTEN",
            "LISTENING",
        }:
            continue
        hp = _split_host_port(m.group("local"))
        if not hp:
            continue
        host, port = hp
        pid, name = _ss_users_from_line(m)
        entries.append(
            PortEntry(
                proto="UDP" if netid.startswith("UDP") else "TCP",
                local_addr=host,
                port=port,
                pid=pid,
                state="LISTENING",
                process_name=name,
            )
        )
    return entries


def _parse_macos_lsof() -> list[PortEntry]:
    entries: list[PortEntry] = []
    _, tcp_text = _hidden_run(["lsof", "-nP", "-iTCP", "-sTCP:LISTEN"])
    _, udp_text = _hidden_run(["lsof", "-nP", "-iUDP"])
    for proto, text in (("TCP", tcp_text), ("UDP", udp_text)):
        for line in text.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 9:
                continue
            name = parts[8]
            hp = _split_host_port(name)
            if not hp:
                continue
            host, port = hp
            try:
                pid = int(parts[1])
            except ValueError:
                continue
            entries.append(
                PortEntry(
                    proto=proto,
                    local_addr=host,
                    port=port,
                    pid=pid,
                    state="LISTENING",
                    process_name=parts[0],
                )
            )
    return entries


def _parse_system() -> list[PortEntry]:
    if sys.platform == "win32":
        return _parse_windows_netstat()
    if sys.platform == "darwin":
        return _parse_macos_lsof()
    return _parse_linux_ss()


def _process_map(pids: Iterable[int]) -> dict[int, tuple[str, str]]:
    info: dict[int, tuple[str, str]] = {}
    wanted = {p for p in pids if p}
    if not wanted:
        return info

    if sys.platform == "win32":
        cmd = (
            "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; "
            "$OutputEncoding=[System.Text.Encoding]::UTF8; "
            "Get-Process | Select-Object Id,ProcessName,Path | "
            "ConvertTo-Json -Compress"
        )
        _, raw = _hidden_run(["powershell", "-NoProfile", "-Command", cmd], timeout=20)
        raw = raw.strip()
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
                    if pid in wanted:
                        info[pid] = (name, path)
        return info

    for pid in wanted:
        name = ""
        path = ""
        if sys.platform.startswith("linux"):
            try:
                path = os.readlink(f"/proc/{pid}/exe")
                name = os.path.basename(path)
            except OSError:
                name = ""
        else:
            _, out = _hidden_run(["ps", "-p", str(pid), "-o", "comm="])
            name = out.strip()
        info[pid] = (name, path)
    return info


def _scan_resolved() -> list[PortEntry]:
    """One full scan: netstat/ss + process map + dedupe."""
    entries = _parse_system()
    pmap = _process_map(e.pid for e in entries)
    for e in entries:
        name, path = pmap.get(e.pid, ("", ""))
        if name:
            e.process_name = name
        if path:
            e.exe_path = path
    seen: set[tuple[str, str, int, int]] = set()
    uniq: list[PortEntry] = []
    for e in entries:
        key = (e.proto.upper(), e.local_addr, e.port, e.pid)
        if key in seen:
            continue
        seen.add(key)
        uniq.append(e)
    uniq.sort(key=lambda x: (x.port, x.proto, x.local_addr, x.pid))
    return uniq


def invalidate_snapshot() -> None:
    """Drop cached scan (call after kill / when freshness matters)."""
    global _snapshot
    _snapshot = None


def list_ports(
    listen_only: bool = True,
    include_pids: set[int] | None = None,
    use_cache: bool = True,
) -> list[PortEntry]:
    global _snapshot
    now = time.monotonic()
    if use_cache and _snapshot is not None and now - _snapshot[0] < _SNAPSHOT_TTL:
        base = list(_snapshot[1])
    else:
        base = _scan_resolved()
        # Stamp AFTER the scan so a slow netstat/PowerShell does not age out immediately
        _snapshot = (time.monotonic(), list(base))

    entries = base
    if listen_only:
        entries = [
            e
            for e in entries
            if e.state in {"LISTENING", "LISTEN"} or e.proto.upper().startswith("UDP")
        ]
    if include_pids is not None:
        entries = [e for e in entries if e.pid in include_pids]
    return list(entries)


def find_port(
    port: int, listen_only: bool = True, use_cache: bool = True
) -> list[PortEntry]:
    return [
        e
        for e in list_ports(listen_only=listen_only, use_cache=use_cache)
        if e.port == port
    ]


def find_by_pid(
    pid: int, listen_only: bool = True, use_cache: bool = True
) -> list[PortEntry]:
    return [
        e
        for e in list_ports(listen_only=listen_only, use_cache=use_cache)
        if e.pid == pid
    ]


def find_by_name(
    name: str, listen_only: bool = True, use_cache: bool = True
) -> list[PortEntry]:
    needle = (name or "").lower()
    if not needle:
        return []
    out: list[PortEntry] = []
    for e in list_ports(listen_only=listen_only, use_cache=use_cache):
        hay = f"{e.process_name} {e.exe_path}".lower()
        if needle in hay:
            out.append(e)
    return out


# Platform-specific protected names. Do not share dwm/csrss with Linux.
PROTECTED_NAMES_WIN = {
    "system",
    "registry",
    "smss",
    "csrss",
    "wininit",
    "winlogon",
    "services",
    "lsass",
    "memcompression",
    "memory compression",
    "idle",
    "system idle process",
    "fontdrvhost",
    "dwm",
    "svchost",
    "spoolsv",
    "alg",
    "lsm",
}
PROTECTED_NAMES_POSIX = {
    "init",
    "systemd",
    "kthreadd",
    "ksoftirqd",
    "migration",
    "rcu_",
}
# Back-compat alias (Windows-only list)
PROTECTED_NAMES = PROTECTED_NAMES_WIN
PROTECTED_PIDS_WIN = {0, 4}


def _basename_name(entry: PortEntry) -> str:
    name = (entry.process_name or "").strip().lower()
    if not name:
        name = (entry.exe_path or "").rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()
    if name.endswith(".exe"):
        name = name[:-4]
    return name


def is_protected_process(entry: PortEntry) -> bool:
    """True if this listener must not be killed by default."""
    if entry.pid == 0:
        return True
    if sys.platform == "win32":
        if entry.pid == 4:
            return True
        names = PROTECTED_NAMES_WIN
    else:
        if entry.pid == 1:
            return True
        names = PROTECTED_NAMES_POSIX
    name = _basename_name(entry)
    if not name:
        return False
    if name in names:
        return True
    # kernel thread prefixes on Linux
    if sys.platform.startswith("linux"):
        for pref in PROTECTED_NAMES_POSIX:
            if name.startswith(pref):
                return True
    return False


def _ss_users_from_line(m: re.Match) -> tuple[int, str]:
    pid = 0
    name = ""
    users = m.group("users") or ""
    pm = _SS_USER_PID.search(users)
    if pm:
        pid = int(pm.group(1))
    nm = _SS_USER_NAME.search(users)
    if nm:
        name = nm.group(1)
    return pid, name


def next_free_port(start: int = 3000, end: int | None = None) -> int | None:
    """First free TCP port in [start, end). TOCTOU: another process may steal it."""
    import socket

    if end is None:
        end = min(start + 5000, 65536)
    end = min(end, 65536)
    start = max(1, start)
    if start >= end:
        return None
    used = {e.port for e in list_ports(listen_only=True)}
    for port in range(start, end):
        if port in used:
            continue
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("0.0.0.0", port))
                return port
            except OSError:
                continue
    return None


def _taskkill(pid: int, force: bool) -> tuple[bool, str]:
    if force:
        args = ["taskkill", "/F", "/T", "/PID", str(pid)]
    else:
        args = ["taskkill", "/T", "/PID", str(pid)]
    completed = subprocess.run(
        args,
        capture_output=True,
        creationflags=0x08000000 if sys.platform == "win32" else 0,
        check=False,
    )
    ok = completed.returncode == 0
    msg = (_decode(completed.stdout) or _decode(completed.stderr) or "").strip()
    first = msg.splitlines()[0] if msg else ("ok" if ok else "failed")
    return ok, first


def kill_port(
    port: int,
    force: bool = False,
    unsafe: bool = False,
) -> list[tuple[PortEntry, bool, str]]:
    """Kill listening holders. Returns full PortEntry for each PID handled."""
    results: list[tuple[PortEntry, bool, str]] = []
    # Fresh scan — do not trust a half-second-old snapshot after other kills
    hits = find_port(port, listen_only=True, use_cache=False)
    if not hits:
        return results

    by_pid: dict[int, PortEntry] = {}
    for e in hits:
        if e.pid:
            by_pid.setdefault(e.pid, e)
    if not by_pid:
        return results

    for pid, entry in sorted(by_pid.items()):
        if is_protected_process(entry) and not unsafe:
            results.append(
                (
                    entry,
                    False,
                    f"protected process skipped (PID {pid} {entry.process_name or '?'})",
                )
            )
            continue
        if sys.platform == "win32":
            ok, first = _taskkill(pid, force)
            results.append((entry, ok, first))
        else:
            args = ["kill", "-9" if force else "-15", str(pid)]
            completed = subprocess.run(args, capture_output=True, check=False)
            ok = completed.returncode == 0
            stderr = completed.stderr.decode("utf-8", errors="replace").strip()
            results.append((entry, ok, stderr or ("ok" if ok else "failed")))
    invalidate_snapshot()
    return results


def kill_ports(
    ports: list[int],
    force: bool = False,
    unsafe: bool = False,
) -> list[tuple[int, PortEntry, bool, str]]:
    out: list[tuple[int, PortEntry, bool, str]] = []
    for port in ports:
        for entry, ok, msg in kill_port(port, force=force, unsafe=unsafe):
            out.append((port, entry, ok, msg))
    return out


def entries_to_json(entries: list[PortEntry]) -> str:
    return json.dumps(
        {
            "schema_version": 1,
            "count": len(entries),
            "entries": [asdict(e) for e in entries],
        },
        ensure_ascii=True,
        indent=2,
    )
