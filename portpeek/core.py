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


def _decode(data: bytes) -> str:
    for enc in ("utf-8-sig", "utf-8", "gbk", "cp936", "latin-1"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace")


def _hidden_run(cmd: list[str]) -> tuple[int, str]:
    creationflags = 0x08000000 if sys.platform == "win32" else 0
    raw = subprocess.run(
        cmd,
        capture_output=True,
        creationflags=creationflags,
        check=False,
    )
    return raw.returncode, _decode(raw.stdout)


def _split_host_port(addr: str) -> tuple[str, int] | None:
    if not addr or addr == "*:*":
        return None
    if addr.startswith("["):
        # [::]:8080 or [::1]:8080
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
            # Windows UDP has no State; treat bound socket as listening
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
        # LISTEN for TCP; UNCONN is normal for UDP listeners
        if netid.startswith("TCP") and state not in {"LISTEN", "LISTENING"}:
            continue
        if netid.startswith("UDP") and state not in {"UNCONN", "UNCONNECTED", "LISTEN", "LISTENING"}:
            continue
        local = m.group("local")
        # ss may show *:22 or 0.0.0.0:22 or [::]:22
        if local.startswith("["):
            hp = _split_host_port(local)
        elif ":" not in local:
            continue
        else:
            hp = _split_host_port(local)
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
    # TCP listeners
    _, tcp_text = _hidden_run(["lsof", "-nP", "-iTCP", "-sTCP:LISTEN"])
    # UDP
    _, udp_text = _hidden_run(["lsof", "-nP", "-iUDP"])
    for proto, text in (("TCP", tcp_text), ("UDP", udp_text)):
        for line in text.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 9:
                continue
            # NAME column often like *:8080 or 127.0.0.1:8080
            name = parts[8]
            if ":" not in name:
                continue
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
    # Linux and other POSIX
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
        _, raw = _hidden_run(
            ["powershell", "-NoProfile", "-Command", cmd]
        )
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
            # macOS / other
            _, out = _hidden_run(["ps", "-p", str(pid), "-o", "comm="])
            name = out.strip()
        info[pid] = (name, path)
    return info


def list_ports(
    listen_only: bool = True,
    include_pids: set[int] | None = None,
) -> list[PortEntry]:
    entries = _parse_system()
    if listen_only:
        entries = [
            e
            for e in entries
            if e.state in {"LISTENING", "LISTEN"} or e.proto.upper().startswith("UDP")
        ]
    if include_pids is not None:
        entries = [e for e in entries if e.pid in include_pids]

    pmap = _process_map(e.pid for e in entries)
    for e in entries:
        name, path = pmap.get(e.pid, ("", ""))
        if name:
            e.process_name = name
        if path:
            e.exe_path = path

    # Keep IPv4 and IPv6 as separate rows
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


def find_port(port: int, listen_only: bool = True) -> list[PortEntry]:
    return [e for e in list_ports(listen_only=listen_only) if e.port == port]


def find_by_pid(pid: int, listen_only: bool = True) -> list[PortEntry]:
    """Reverse lookup: which ports does this PID hold?"""
    return [e for e in list_ports(listen_only=listen_only) if e.pid == pid]


def find_by_name(name: str, listen_only: bool = True) -> list[PortEntry]:
    """Case-insensitive substring match on process name or exe path."""
    needle = (name or "").lower()
    if not needle:
        return []
    out: list[PortEntry] = []
    for e in list_ports(listen_only=listen_only):
        hay = f"{e.process_name} {e.exe_path}".lower()
        if needle in hay:
            out.append(e)
    return out


# Critical OS processes — never taskkill by default
PROTECTED_PIDS_WIN = {0, 4}  # Idle, System
PROTECTED_NAMES = {
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
}


def is_protected_process(entry: PortEntry) -> bool:
    """True if this listener must not be killed by default."""
    if sys.platform == "win32" and entry.pid in PROTECTED_PIDS_WIN:
        return True
    name = (entry.process_name or "").strip().lower()
    if not name:
        # path basename fallback
        name = (entry.exe_path or "").rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()
    if name.endswith(".exe"):
        name = name[:-4]
    if name in PROTECTED_NAMES:
        return True
    # lsass.exe etc already stripped; also match "System" from netstat
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


def next_free_port(start: int = 3000, end: int = 10000) -> int | None:
    """First free TCP port in [start, end). One netstat/ss snapshot."""
    import socket

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
    """Kill listening holders. Skips protected OS processes unless unsafe=True.

    Admin permission hint is applied by the CLI layer only.
    """
    results: list[tuple[PortEntry, bool, str]] = []
    hits = find_port(port, listen_only=True)
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
            results.append((PortEntry("", "", port, pid, ""), ok, first))
        else:
            args = ["kill", "-9" if force else "-15", str(pid)]
            completed = subprocess.run(args, capture_output=True, check=False)
            ok = completed.returncode == 0
            stderr = completed.stderr.decode("utf-8", errors="replace").strip()
            results.append(
                (PortEntry("", "", port, pid, ""), ok, stderr or ("ok" if ok else "failed"))
            )
    return results


def kill_ports(
    ports: list[int],
    force: bool = False,
    unsafe: bool = False,
) -> list[tuple[int, PortEntry, bool, str]]:
    """Kill multiple ports. Returns (port, entry, ok, message)."""
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
