# 分发文案（可直接复制）

---

## A. V2EX / 掘金 · 中文

**标题建议（三选一）：**

1. `portpeek：一条命令查出谁占了你的 3000 端口，还能安全干掉`
2. `Windows 上终于不用翻任务管理器找端口了：portpeek`
3. `pip install portpeek，解决 EADDRINUSE（附系统进程保护）`

**正文：**

---

做 Windows 前端/后端/本地联调，最烦的循环之一：

```
Error: listen EADDRINUSE: address already in use :::3000
```

然后开任务管理器翻半天，或者记一串：

```
netstat -ano | findstr :3000
taskkill /PID xxx /F
```

我做了个小 CLI：**[portpeek](https://github.com/jsunnx/portpeek)**，已上 PyPI。

```bash
pip install portpeek
portpeek 3000
```

输出长这样：

```text
Port 3000 is in use:

PROTO  PORT  PID  STATE     PROCESS     ADDRESS
-----  ----  ---  --------  ----------  ----------------
TCP    3000  452  LISTENING node.exe    0.0.0.0
TCP    3000  452  LISTENING node.exe    [::]
UDP    3000  452  LISTENING node.exe    0.0.0.0

To free it: portpeek 3000 --kill
```

**和常见 kill-port 脚本比，我多做了几件事：**

1. **显示进程名 + 完整路径**（不只是 PID）
2. **TCP + UDP，IPv4 + IPv6 分行**（双栈不会被吞掉）
3. **默认不杀系统进程**——`System` / `lsass` / `csrss` 会直接 skip，不给你蓝屏机会；真要杀得 `--unsafe`
4. 反查：`portpeek --pid 1234`、`portpeek --name node`
5. 找空闲端口：`portpeek --free`
6. 批量：`portpeek 3000 5173 8080 --kill`
7. 纯 Python 标准库，零第三方依赖

仓库：https://github.com/jsunnx/portpeek  
PyPI：https://pypi.org/project/portpeek/

有点用的话点个 Star，谢谢。

---

## B. Hacker News · Show HN（英文）

**标题：**

`Show HN: Portpeek – find what’s using your port and kill it safely`

**正文：**

---

Every local dev eventually hits `EADDRINUSE`, then digs through Task Manager or pastes `netstat -ano | findstr`.

[Portpeek](https://github.com/jsunnx/portpeek) is a tiny Python CLI:

```bash
pip install portpeek
portpeek 3000
```

It prints protocol, port, PID, process name, and bind address (IPv4 + IPv6, TCP + UDP). Then:

```bash
portpeek 3000 --kill
```

**What makes it less annoying than a one-off kill-port script:**

- Process **name and executable path**, not just a PID  
- **UDP** (Windows `netstat` UDP rows have no State column — most parsers drop them)  
- **Refuses to kill critical OS processes** by default (`lsass`, `System`, `csrss`, …). Escape hatch: `--unsafe`  
- `--pid` reverse lookup, `--name` filter, `--free` unused port, multi-port batch kill  
- Zero third-party dependencies  

Works best on Windows; Linux (`ss`) and macOS (`lsof`) are best-effort.

GitHub: https://github.com/jsunnx/portpeek  
PyPI: https://pypi.org/project/portpeek/

Would love bug reports / PRs.

---

## C. Reddit r/Python

**标题：**

`I built portpeek: see which process holds a port (TCP+UDP) and free it safely`

**正文：**

When a dev server dies with `EADDRINUSE`, the usual dance is Task Manager or a pile of `netstat`/`taskkill` commands.

**portpeek** is a small CLI for that one job:

```bash
pip install portpeek
portpeek 3000
portpeek 3000 --kill
```

Highlights:

- Process name + path, dual-stack (IPv4/IPv6), TCP **and** UDP  
- Protects system processes by default  
- `--pid`, `--name`, `--free`, batch ports, JSON with `schema_version`  
- No third-party deps  

Links: [GitHub](https://github.com/jsunnx/portpeek) · [PyPI](https://pypi.org/project/portpeek/)

---

## 发帖渠道 checklist

| 渠道 | 用哪篇 | 注意 |
|------|--------|------|
| V2EX `分享创造` | A | 别硬广，语气像在写踩坑记录 |
| 掘金 | A | 可加代码块截图 |
| HN `Show HN` | B | 标题别夸张，别写 “blazing fast” |
| r/Python | C | 有人问 platform 再回帖 |

**不要：** 一次多账号刷屏；同一天全渠道轰炸。隔 1–2 天发一地即可。
