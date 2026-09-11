# portpeek

**Who is occupying my port 3000 / 5173 / 8080?**

One command to find the process holding a port — and free it.

No more hunting in Task Manager, no more `netstat -ano | findstr`.

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

## Install

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
| **Windows** (primary) | `netstat -ano` + PowerShell process map |
| Linux | `ss -tulnp` + `/proc` |
| macOS | `lsof` |

Windows is fully supported. Linux/macOS are best-effort and may miss edge cases (restricted processes, missing tools in PATH).

---

## Usage

```bash
portpeek                 # list all LISTEN / bound ports (TCP + UDP)
portpeek 3000            # inspect one port
portpeek --all           # not only LISTEN (include ESTABLISHED, etc.)
portpeek --json          # machine-readable output (ASCII-safe JSON)
portpeek 3000 --kill     # terminate listening process(es) on 3000
portpeek 3000 --kill --force
python -m portpeek 8080  # no install needed
```

`--kill` only targets **listening** holders (not `TIME_WAIT` leftovers). After kill, success is judged by whether the port is still **listening**, not by stray connection states.

---

## Common cases

| You hit this | Run this |
|--------------|----------|
| Next / Vite won't start | `portpeek 3000` |
| Need free ports | `portpeek` |
| Script needs a yes/no | `portpeek 8080 --json` |
| You must use that port | `portpeek 8080 --kill` |
| Stubborn leftover | `portpeek 8080 --kill --force` |

---

## Design notes

- **Zero third-party deps**: stdlib + system tools
- **Read-only by default**: killing requires an explicit `--kill`
- **IPv4 + IPv6 kept separate**: dual-stack binds are not merged away
- **UDP included**: Windows UDP rows have no State column; they are treated as bound/listening
- **Process tree kill**: Windows uses `taskkill /T` (and `/F` with `--force`)
- **JSON is portable**: `ensure_ascii=True` so redirected output stays valid on GBK consoles
- **No elevation tricks**: if you lack rights, it fails cleanly

---

## Library API

```python
from portpeek import list_ports, find_port, kill_port

for e in list_ports():
    print(e.port, e.pid, e.process_name, e.local_addr)

find_port(3000)
kill_port(3000, force=False)  # listening holders only
```

---

## License

MIT

---

If this saves you one Task Manager scavenger hunt, a **Star** is enough. Issues welcome.
