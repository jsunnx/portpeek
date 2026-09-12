# portpeek

[![PyPI version](https://img.shields.io/pypi/v/portpeek.svg)](https://pypi.org/project/portpeek/)
[![Python](https://img.shields.io/pypi/pyversions/portpeek.svg)](https://pypi.org/project/portpeek/)
[![CI](https://github.com/jsunnx/portpeek/actions/workflows/ci.yml/badge.svg)](https://github.com/jsunnx/portpeek/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**Who is occupying my port 3000 / 5173 / 8080?**

One command to find the process holding a port — and free it.

No more hunting in Task Manager, no more `netstat -ano | findstr`.

Keywords: **port killer · kill-port · EADDRINUSE · netstat · Windows · Linux · TCP · UDP · CLI**

```text
$ portpeek 3000

Port 3000 is in use:

PROTO  PORT  PID  STATE     PROCESS     ADDRESS
-----  ----  ---  --------  ----------  ----------------
TCP    3000  452  LISTENING node.exe    0.0.0.0
TCP    3000  452  LISTENING node.exe    [::]
UDP    3000  452  LISTENING node.exe    0.0.0.0

To free it: portpeek 3000 --kill
```

---

## Why

On Windows, this loop is familiar:

1. Local server fails to start
2. `Error: listen EADDRINUSE`
3. Who has the port?
4. Dig through Task Manager
5. Fight admin / non-admin prompts

`portpeek` does one job well: **show who holds a port, and kick it out.**

---

## vs other port killers

| | portpeek | generic `kill-port` scripts |
|--|----------|-----------------------------|
| Shows **process name + path** | yes | often only PID |
| Lists **TCP + UDP**, IPv4 + IPv6 | yes | frequently TCP-only |
| **Protects OS processes** (lsass, System, …) | yes (`--kill` skips them) | usually no |
| Reverse lookup `--pid` / `--name` | yes | rare |
| Free-port picker `--free` | yes | rare |
| Zero Python deps | yes | varies |
| macOS / Linux best-effort | yes | sometimes |

---

## Install

```bash
pip install portpeek
```

Or from source:

```bash
git clone https://github.com/jsunnx/portpeek.git
cd portpeek
pip install -e .
```

Or run without installing:

```bash
python -m portpeek
```

Requires Python **3.9+**.

| OS | How it reads ports |
|----|--------------------|
| **Windows** (primary, tested) | `netstat -ano` + PowerShell process map |
| Linux | `ss -tulnp` + `/proc` (best-effort, less tested) |
| macOS | `lsof` (best-effort, less tested) |

If you only care about Windows, it is fully supported. POSIX paths are community-grade.

---

## Usage

```bash
portpeek                     # list LISTEN / bound ports (TCP + UDP, IPv4 + IPv6)
portpeek 3000                # inspect one port
portpeek 3000 5173 8080      # inspect several ports
portpeek --pid 1234          # reverse: which ports does this PID hold?
portpeek --name node         # filter by process name substring
portpeek --free              # print a free TCP port (from 3000)
portpeek --free 8000         # free port starting search at 8000
portpeek --watch 2           # poll until the port state changes
portpeek --sort name         # sort by port | pid | name
portpeek --all               # include non-LISTEN states
portpeek --json              # JSON object with schema_version=1
portpeek --json -o ports.json  # write UTF-8 JSON file
portpeek 3000 5173 --kill    # batch free
portpeek 3000 --kill --force
portpeek 3000 --kill --unsafe  # allow killing protected OS processes
portpeek --no-color          # plain text (CI / pipes)
```

JSON shape (`schema_version` is stable for scripts):

```json
{
  "schema_version": 1,
  "count": 2,
  "entries": [
    {"proto": "TCP", "local_addr": "0.0.0.0", "port": 3000, "pid": 452, "state": "LISTENING", "process_name": "node", "exe_path": "..."}
  ]
}
```

### System process protection

`--kill` **never** targets critical OS processes by default:

Windows: `System` (PID 4), `Idle`, `lsass`, `csrss`, `smss`, `wininit`, `winlogon`, `services`, `Registry`, `Memory Compression`, `dwm`, **`svchost`**, **`spoolsv`**, …  
POSIX: PID 0/1, `init`, `systemd`, kernel threads.

If only a protected process holds the port, you get a clear skip message.  
Override only with `--unsafe` (combine with `--force` if needed) — you can blue-screen or lock yourself out. Don't.

Snapshots are reused for ~0.8s so multi-port / kill paths do not re-run `netstat`+PowerShell for every call. `--kill` and `--watch` force a fresh scan when needed.

### JSON / redirect notes (Windows)

- Prefer `portpeek --json -o out.json` — writes UTF-8 with no BOM.
- PowerShell 5.1 `>` re-encodes text to UTF-16. For byte-faithful redirect use:

```powershell
cmd /c "python -m portpeek --json > out.json"
# or
python -m portpeek --json -o out.json
```

### Kill semantics

- Only **listening** holders are killed (not `TIME_WAIT` leftovers).
- Windows uses `taskkill /T` (process tree); `--force` adds `/F`.
- After kill, success means the port is no longer **listening**.
- Access denied → message suggests running as Administrator.

---

## Common cases

| You hit this | Run this |
|--------------|----------|
| Next / Vite won't start | `portpeek 3000` |
| Who owns this PID? | `portpeek --pid 4521` |
| Where is node? | `portpeek --name node` |
| Need a free port for a script | `portpeek --free` |
| Script needs JSON | `portpeek 8080 --json` |
| You must use that port | `portpeek 8080 --kill` |

---

## Design notes

- **Zero third-party deps**
- **Read-only by default**: `--kill` is explicit
- **IPv4 + IPv6 kept separate** (dual-stack not merged)
- **UDP included**: Windows UDP rows have no State column
- **Portable JSON**: `ensure_ascii=True`
- **UTF-8 console** on Windows for process names

---

## Library API

```python
from portpeek import list_ports, find_port, find_by_pid, find_by_name, next_free_port, kill_port

list_ports()
find_port(3000)
find_by_pid(4521)
find_by_name("node")
next_free_port(3000)
kill_port(3000, force=False)
```

---

## Tests

```bash
python -m unittest discover -s tests -v
```

---

## License

MIT

---

If this saves you one Task Manager scavenger hunt, a **Star** is enough. Issues welcome.
