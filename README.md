# portpeek

**Who is occupying my port 3000 / 5173 / 8080?**

One command to find the process holding a port — and free it.

No more hunting in Task Manager, no more `netstat -ano | findstr`.

```text
$ portpeek 3000

Port 3000 is in use:

PROTO  PORT  PID  STATE     PROCESS     PATH
-----  ----  ---  --------  ----------  --------------------------------
TCP    3000  452  LISTENING node.exe    C:\Program Files\nodejs\node.exe

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

Requires Python **3.9+**. Windows is the primary target; Linux/macOS work too (via `netstat`).

---

## Usage

```bash
portpeek                 # list all LISTEN ports
portpeek 3000            # inspect one port
portpeek --all           # not only LISTEN (include ESTABLISHED, etc.)
portpeek --json          # machine-readable output
portpeek 3000 --kill     # terminate the process holding 3000
portpeek 3000 --kill --force
python -m portpeek 8080  # no install needed
```

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

- **Zero third-party deps**: stdlib + system `netstat` / PowerShell  
- **Read-only by default**: killing requires an explicit `--kill`  
- **Scriptable**: stable `--json` fields  
- **No elevation tricks**: if you lack rights, it fails cleanly  

---

## Library API

```python
from portpeek import list_ports, find_port, kill_port

for e in list_ports():
    print(e.port, e.pid, e.process_name, e.exe_path)

find_port(3000)
kill_port(3000, force=False)
```

---

## License

MIT

---

If this saves you one Task Manager scavenger hunt, a **Star** is enough. Issues welcome.
