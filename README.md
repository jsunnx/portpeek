# portpeek

**谁占了我的 3000 / 5173 / 8080？**

一行命令查端口，顺手结束进程。不用再开资源管理器点点点，也不用背 `netstat -ano | findstr`。

```text
PS> portpeek 3000

端口 3000 被占用:

PROTO  PORT  PID  STATE     PROCESS     PATH
-----  ----  ---  --------  ----------  --------------------------------
TCP    3000  452  LISTENING node.exe    C:\Program Files\nodejs\node.exe

若要释放: portpeek 3000 --kill
```

---

## 为什么是它

Windows 上开发时最烦的事之一：

1. 起不了本地服务  
2. `Error: listen EADDRINUSE`  
3. 不知道谁占着  
4. 资源管理器找半天  
5. 管理员 / 非管理员、任务管理器权限来回切  

`portpeek` 只做一件事：**看谁占端口，并且能一键踢掉。**

---

## 安装

```bash
git clone https://github.com/jsunnx/portpeek.git
cd portpeek
pip install -e .
```

或不安装，直接跑：

```bash
python -m portpeek
```

Python **3.9+**。Windows 为一等公民，Linux / macOS 也能用（走 `netstat`）。

---

## 用法

```bash
portpeek              # 列出所有 LISTEN 端口
portpeek 3000         # 只查 3000
portpeek --all        # 不只 LISTEN，含 ESTABLISHED 等
portpeek --json       # JSON 输出（方便接脚本）
portpeek 3000 --kill  # 结束占用 3000 的进程（普通结束）
portpeek 3000 --kill --force   # 强制结束
python -m portpeek 8080        # 不装包也能用
```

---

## 常见场景

| 你遇到的问题 | 命令 |
|--------------|------|
| Next / Vite 起不来 | `portpeek 3000` |
| 想看还剩什么空闲 | `portpeek` |
| 脚本里判断端口是否被占 | `portpeek 8080 --json` |
| 要真用这个端口了 | `portpeek 8080 --kill` |
| 顽固残留 | `portpeek 8080 --kill --force` |

---

## 设计取舍

- **零依赖**：标准库 + 系统自带 `netstat` / PowerShell  
- **只读默认**：默认只查看，杀进程必须显式 `--kill`  
- **可脚本化**：`--json` 输出稳定字段  
- **不越权**：不会自己提权；权限不够就失败并说明  

---

## API

也能当库用：

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

如果它帮你省了一次「任务管理器翻找」，点一下 **Star** 就够了。有问题欢迎开 Issue。
