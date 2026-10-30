#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AI Agent 全栈行为感知与安全哨兵舱 (Agent Sentinel) — Linux 独立源文件版 (v8.0)
================================================================================
零第三方依赖（仅使用 Python 3 标准库 + Linux /proc 内核伪文件系统 + Tkinter/CLI 双模）：
1. 【Linux /proc 内核级极速探测】
   - 直接读取 /proc/<pid>/cmdline、/proc/<pid>/stat、/proc/<pid>/status (VmRSS 内存)，
     并通过 os.readlink('/proc/<pid>/cwd') 零开销获取后台进程的真实工作目录 (Live CWD)。
   - 直接解析 /proc/net/tcp 与 /proc/net/tcp6 关联 socket inode，毫秒级透视 IPv4/IPv6 监听端口与外联 IP。
2. 【双击任意行跳出“单命令专属独立监控窗”（无需暂停主监控流）】
   - 在 GUI 主表中直接双击任意一行（或按 Enter 键），立即弹出非模态独立窗口（同一命令自动去重唤醒）；
   - 独立窗口实时同步该命令的耗时、内存、端口、派生子进程及运行期间修改的文件清单；
   - 独立窗口内置：【⏸ 冻结此命令树 (SIGSTOP)】、【▶ 恢复运行 (SIGCONT)】、【🛑 强杀进程树 (SIGKILL)】、
     【📂 打开工作目录 (xdg-open)】、【💾 导出 Markdown 取证单 (.md)】。
3. 【多 Agent 实例自动分流 + 按 Agent 独立报错死循环熔断】
   - 6 层父进程溯源自动识别 Cursor、Claude Code、Windsurf、VS Code、Aider、PyCharm、OpenInterpreter 等宿主；
   - 支持按单 Agent 通道筛选与精准冻结，连续报错死循环计数器按 Agent 实例独立隔离。
4. 【进程 ➔ 文件改动因果归因 + 双轨文件时光机 (Baseline + PrevVersion)】
   - 自动建立工作区初始基线与每次修改前的滚动快照，支持 unified_diff 行级对比与一键回退。
5. 【GUI / CLI 全环境自适应】
   - 桌面环境 (X11 / Wayland) 默认启动深色 GUI 悬浮舱；无桌面环境 (SSH / 容器) 自动平滑切换至 CLI 交互模式。
"""

import argparse
import base64
import difflib
import os
import re
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(line_buffering=True)
    except Exception:
        pass


# 监控的目标二进制集合（涵盖 Linux 常用 Shell、构建工具、语言运行时与云 CLI）
WATCHED_BINARIES = {
    "sh", "bash", "zsh", "dash", "fish", "pwsh", "tmux", "screen",
    "git", "gh", "rg", "grep", "find", "sed", "awk", "curl", "wget", "ssh", "scp", "rsync", "tar",
    "node", "npm", "npx", "pnpm", "yarn", "bun", "deno",
    "python", "python3", "pip", "pip3", "uv", "poetry", "conda", "pytest",
    "go", "cargo", "rustc", "dotnet", "java", "javac", "mvn", "gradle",
    "gcc", "g++", "clang", "make", "cmake", "ninja", "php", "ruby",
    "docker", "podman", "kubectl", "helm", "terraform", "aws", "az", "gcloud"
}

AGENT_HOST_PATTERNS = re.compile(
    r"^(cursor|claude|windsurf|trae|code|code-insiders|aider|pycharm|idea|webstorm|goland|clion|ollama|openinterpreter)$",
    re.IGNORECASE,
)

BACKUP_ROOT = Path(tempfile.gettempdir()) / "AgentSentinel_ShadowBackups_Linux"


def decode_command_payload(cmdline: str) -> str:
    """自动解码命令中的 Base64 载荷（base64 -d / python -c b64decode / sh -c 剥壳）"""
    if not cmdline:
        return ""
    notes = []

    # 1. 检测 echo <b64> | base64 -d
    for m in re.finditer(r"echo\s+['\"]?([A-Za-z0-9+/=]{12,})['\"]?\s*\|\s*base64\s+-d", cmdline):
        try:
            raw = base64.b64decode(m.group(1)).decode("utf-8", errors="replace").strip()
            if raw:
                notes.append(f"[Base64 管道解码]:\n{raw}")
        except Exception:
            pass

    # 2. 检测 b64decode('...')
    for m in re.finditer(r"b64decode\(['\"]([A-Za-z0-9+/=]{12,})['\"]\)", cmdline):
        try:
            raw = base64.b64decode(m.group(1)).decode("utf-8", errors="replace").strip()
            if raw:
                notes.append(f"[Python 内联 Base64 解码]:\n{raw}")
        except Exception:
            pass

    # 3. 检测 bash/sh -c "..."
    m_sh = re.search(r"\b(?:ba|z|da)?sh\s+-[a-z]*c\s+(.+)$", cmdline)
    if m_sh:
        payload = m_sh.group(1).strip().strip("'\"")
        notes.append(f"[Shell -c 剥壳载荷]:\n{payload}")

    return "\n----------------------------------------\n".join(notes)


def evaluate_command_risk(cmdline: str, decoded: str) -> dict:
    """评估 Linux 后台命令风险等级（含剪贴板窃取、SSH/云密钥读取与破坏性指令检测）"""
    full_text = f"{cmdline}\n{decoded}"

    high_risk_rules = [
        (r"(?i)\b(xclip|xsel|wl-paste)\b", "尝试后台静默读取 Linux 剪贴板"),
        (r"(?i)(\.env\b|id_rsa|id_ed25519|authorized_keys|\.aws/credentials|\.kube/config|/etc/shadow)", "触碰高敏感密钥或系统凭据文件"),
        (r"(?i)\b(rm\s+-[rRfF]{2,}|rm\s+-r\s+-f|find\b.*-delete|shred\b|mkfs\b|dd\s+if=)", "递归强制删除文件或磁盘级破坏"),
        (r"(?i)\bgit\s+(reset\s+--hard|clean\s+-[fd]|push\s+.*(-f|--force)|checkout\s+--\s+\.)", "不可逆的 Git 历史重置或丢弃工作区修改"),
        (r"(?i)\b(kill\s+-9|killall\b|pkill\s+-9|chmod\s+-R\s+777|chown\s+-R)", "危险权限变更或强制杀进程"),
        (r"(?i)\b(curl|wget)\b.*\|\s*(sh|bash|zsh|python|python3)\b", "远程下载脚本并直接通过管道执行"),
    ]
    for pat, reason in high_risk_rules:
        m = re.search(pat, full_text)
        if m:
            return {"level": "高危", "badge": "🔴 高危", "score": 3, "reason": f"{reason} ({m.group(0)})"}

    medium_risk_rules = [
        (r"(?i)\b(printenv|env\b|export\s+-p)", "枚举当前系统环境变量"),
        (r"(?i)\b(npm\s+i|npm\s+install|pip\s+install|pnpm\s+add|yarn\s+add|cargo\s+add|apt\s+install|apt-get\s+install)", "安装外部第三方依赖包"),
        (r"(?i)\bgit\s+(commit|push|merge|rebase|stash|branch\s+-[dD])", "变更 Git 仓库提交状态"),
        (r"(?i)\b(mv\b|cp\b|mkdir\b|tee\b|sed\s+-i)", "写入或修改本地文件"),
        (r"(?i)\b(curl\b|wget\b|ssh\b|scp\b|rsync\b|docker\s+run|kubectl\s+apply|gh\s+pr)", "发起外部网络请求或容器部署"),
    ]
    for pat, reason in medium_risk_rules:
        m = re.search(pat, full_text)
        if m:
            return {"level": "修改", "badge": "🟡 修改", "score": 2, "reason": f"{reason} ({m.group(0)})"}

    return {"level": "只读", "badge": "🟢 只读", "score": 1, "reason": "常规只读查询或状态检查"}


class LinuxProcInspector:
    """基于 Linux /proc 伪文件系统的零开销内核遥测与进程树控制器"""

    def __init__(self, extra_names=None):
        self.watched = set(WATCHED_BINARIES)
        if extra_names:
            for name in extra_names:
                if name:
                    self.watched.add(name.lower().strip())
        self.parent_cache = {}
        self.clk_tck = os.sysconf(os.sysconf_names.get("SC_CLK_TCK", "SC_CLK_TCK")) if hasattr(os, "sysconf") else 100

    def read_proc_comm(self, pid: int) -> str:
        try:
            with open(f"/proc/{pid}/comm", "r", encoding="utf-8", errors="replace") as f:
                return f.read().strip()
        except Exception:
            return ""

    def read_proc_stat_basic(self, pid: int):
        """解析 /proc/<pid>/stat 获取 (comm, state, ppid, cpu_sec)"""
        try:
            with open(f"/proc/{pid}/stat", "r", encoding="utf-8", errors="replace") as f:
                data = f.read()
            lpar = data.find("(")
            rpar = data.rfind(")")
            if lpar == -1 or rpar == -1:
                return None
            comm = data[lpar + 1:rpar]
            rest = data[rpar + 2:].split()
            state = rest[0]
            ppid = int(rest[1])
            utime = int(rest[11])
            stime = int(rest[12])
            cpu_sec = round((utime + stime) / float(self.clk_tck), 1)
            return comm, state, ppid, cpu_sec
        except Exception:
            return None

    def read_proc_cmdline(self, pid: int) -> str:
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                raw = f.read()
            if not raw:
                return ""
            parts = [p.decode("utf-8", errors="replace") for p in raw.rstrip(b"\x00").split(b"\x00")]
            return " ".join(parts).strip()
        except Exception:
            return ""

    def read_proc_cwd(self, pid: int) -> str:
        try:
            return os.readlink(f"/proc/{pid}/cwd")
        except Exception:
            return ""

    def read_proc_rss_mb(self, pid: int) -> float:
        try:
            with open(f"/proc/{pid}/status", "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    if line.startswith("VmRSS:"):
                        kb = int(line.split()[1])
                        return round(kb / 1024.0, 1)
        except Exception:
            pass
        return 0.0

    def get_ancestry_and_agent(self, start_ppid: int):
        chain = []
        curr = start_ppid
        depth = 0
        detected_agent = None
        top_non_shell = None

        while curr > 2 and depth < 6:
            info = self.read_proc_stat_basic(curr)
            if info:
                comm, _, next_ppid, _ = info
                self.parent_cache[curr] = (comm, next_ppid)
            elif curr in self.parent_cache:
                comm, next_ppid = self.parent_cache[curr]
            else:
                comm, next_ppid = f"已退出({curr})", 0

            node_str = f"{comm}({curr})"
            if AGENT_HOST_PATTERNS.match(comm):
                node_str = f"🤖{node_str}"
                detected_agent = f"🤖 {comm} #{curr}"
            elif comm.lower() not in {"systemd", "init", "sshd", "gnome-terminal-", "konsole", "kitty", "alacritty", "wezterm-gui"}:
                top_non_shell = f"⚙️ {comm} #{curr}"

            chain.append(node_str)
            if comm.lower() in {"systemd", "init"} or next_ppid <= 2 or next_ppid == curr:
                break
            curr = next_ppid
            depth += 1

        chain.reverse()
        chain_str = " ➔ ".join(chain) if chain else "未知宿主"
        agent_id = detected_agent or top_non_shell or "⚙️ 独立终端"
        return chain_str, agent_id

    def get_tcp_summary_for_pid(self, pid: int) -> str:
        """通过 /proc/<pid>/fd 与 /proc/net/tcp[6] 关联该进程的监听端口与外联地址"""
        inodes = set()
        try:
            fd_dir = f"/proc/{pid}/fd"
            for fd_name in os.listdir(fd_dir):
                try:
                    target = os.readlink(f"{fd_dir}/{fd_name}")
                    if target.startswith("socket:[") and target.endswith("]"):
                        inodes.add(target[8:-1])
                except Exception:
                    pass
        except Exception:
            return ""

        if not inodes:
            return ""

        results = []
        for net_file, is_v6 in (("/proc/net/tcp", False), ("/proc/net/tcp6", True)):
            if not os.path.exists(net_file):
                continue
            try:
                with open(net_file, "r", encoding="utf-8") as f:
                    lines = f.readlines()[1:]
                for line in lines:
                    parts = line.split()
                    if len(parts) < 10 or parts[9] not in inodes:
                        continue
                    state_hex = parts[3]
                    local_hex, lport_hex = parts[1].split(":")
                    rem_hex, rport_hex = parts[2].split(":")
                    lport = int(lport_hex, 16)
                    rport = int(rport_hex, 16)
                    if state_hex == "0A":  # TCP_LISTEN
                        tag = f"监听:{lport}"
                        if tag not in results:
                            results.append(tag)
                    elif state_hex == "01":  # TCP_ESTABLISHED
                        if not is_v6:
                            ip_int = int(local_hex, 16)
                            rem_int = int(rem_hex, 16)
                            rem_ip = socket.inet_ntoa(struct.pack("<L", rem_int))
                            if rem_ip not in ("127.0.0.1", "0.0.0.0"):
                                tag = f"外联:{rem_ip}:{rport}"
                                if tag not in results:
                                    results.append(tag)
            except Exception:
                pass
        return ", ".join(results)

    def get_descendant_pids(self, root_pid: int) -> list:
        """获取指定进程及其所有子孙进程的 PID 列表"""
        children_map = {}
        for entry in os.listdir("/proc"):
            if not entry.isdigit():
                continue
            p = int(entry)
            info = self.read_proc_stat_basic(p)
            if info:
                _, _, ppid, _ = info
                children_map.setdefault(ppid, []).append(p)

        result = [root_pid]
        queue = [root_pid]
        while queue:
            curr = queue.pop(0)
            for child in children_map.get(curr, []):
                if child != os.getpid() and child not in result:
                    result.append(child)
                    queue.append(child)
        return result

    def suspend_tree(self, root_pid: int) -> bool:
        pids = self.get_descendant_pids(root_pid)
        ok = False
        for p in pids:
            try:
                os.kill(p, signal.SIGSTOP)
                ok = True
            except Exception:
                pass
        return ok

    def resume_tree(self, root_pid: int) -> bool:
        pids = self.get_descendant_pids(root_pid)
        ok = False
        for p in pids:
            try:
                os.kill(p, signal.SIGCONT)
                ok = True
            except Exception:
                pass
        return ok

    def kill_tree(self, root_pid: int) -> bool:
        pids = self.get_descendant_pids(root_pid)
        pids.reverse()
        ok = False
        for p in pids:
            try:
                os.kill(p, signal.SIGKILL)
                ok = True
            except Exception:
                pass
        return ok


class WorkspaceSnapshotManager:
    """工作区双轨微快照管理 (Baseline 初始基线 + PrevVersion 滚动上一版本) 与轻量轮询检测器"""

    IGNORE_DIRS = {".git", "node_modules", "__pycache__", "dist", "build", ".next", "target", "venv", ".venv"}

    def __init__(self, workspace_path: str):
        self.workspace = Path(workspace_path).resolve()
        BACKUP_ROOT.mkdir(parents=True, exist_ok=True)
        self.base_dir = BACKUP_ROOT / "Baseline"
        self.work_dir = BACKUP_ROOT / "WorkingCopy"
        self.prev_dir = BACKUP_ROOT / "PrevVersion"
        self.file_mtimes = {}
        self.suppress_until = 0.0

    def initialize_baseline(self) -> int:
        if not self.workspace.exists():
            return 0
        count = 0
        for root, dirs, files in os.walk(self.workspace):
            dirs[:] = [d for d in dirs if d not in self.IGNORE_DIRS]
            for fname in files:
                if fname.endswith((".tmp", ".swp", ".pyc", ".log")):
                    continue
                fpath = Path(root) / fname
                try:
                    st = fpath.stat()
                    if st.st_size > 2 * 1024 * 1024:
                        continue
                    rel = fpath.relative_to(self.workspace)
                    self.file_mtimes[str(rel)] = st.st_mtime_ns
                    for target_root in (self.base_dir, self.work_dir):
                        dest = target_root / rel
                        dest.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copy2(fpath, dest)
                    count += 1
                    if count >= 2000:
                        return count
                except Exception:
                    pass
        return count

    def scan_changes(self) -> list:
        if time.time() < self.suppress_until or not self.workspace.exists():
            return []
        events = []
        current_seen = set()

        for root, dirs, files in os.walk(self.workspace):
            dirs[:] = [d for d in dirs if d not in self.IGNORE_DIRS]
            for fname in files:
                if fname.endswith((".tmp", ".swp", ".pyc", ".log")):
                    continue
                fpath = Path(root) / fname
                try:
                    rel_str = str(fpath.relative_to(self.workspace))
                    current_seen.add(rel_str)
                    mtime = fpath.stat().st_mtime_ns
                    if rel_str not in self.file_mtimes:
                        self.file_mtimes[rel_str] = mtime
                        events.append(self._archive_and_build_event("Created", rel_str, fpath))
                    elif self.file_mtimes[rel_str] != mtime:
                        self.file_mtimes[rel_str] = mtime
                        events.append(self._archive_and_build_event("Changed", rel_str, fpath))
                except Exception:
                    pass

        deleted = set(self.file_mtimes.keys()) - current_seen
        for rel_str in deleted:
            del self.file_mtimes[rel_str]
            events.append(self._archive_and_build_event("Deleted", rel_str, self.workspace / rel_str))

        return events

    def _archive_and_build_event(self, change_type: str, rel_str: str, full_path: Path) -> dict:
        base_snap = self.base_dir / rel_str
        work_snap = self.work_dir / rel_str
        prev_snap = self.prev_dir / rel_str

        if work_snap.exists():
            prev_snap.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(work_snap, prev_snap)

        if full_path.is_file() and full_path.stat().st_size < 2 * 1024 * 1024:
            work_snap.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(full_path, work_snap)

        has_base = base_snap.exists()
        has_prev = prev_snap.exists()
        status = (
            "🛡️ 基线 + 上一版本双快照就绪" if (has_base and has_prev)
            else "🛡️ 初始基线快照就绪" if has_base
            else "🔄 新建文件 (已保存上一版本)" if has_prev
            else "🆕 新建文件 (首次写入已归档)"
        )
        badge = {"Created": "🟢 新建文件", "Deleted": "🔴 删除文件"}.get(change_type, "📝 修改内容")
        return {
            "time_str": datetime.now().strftime("%H:%M:%S.%f")[:-3],
            "change_type": change_type,
            "badge": badge,
            "rel_path": rel_str,
            "full_path": str(full_path),
            "status": status,
            "base_path": str(base_snap) if has_base else "",
            "prev_path": str(prev_snap) if has_prev else "",
        }

    def rollback_file(self, full_path_str: str, snap_path_str: str) -> bool:
        self.suppress_until = time.time() + 1.0
        target = Path(full_path_str)
        if snap_path_str and Path(snap_path_str).exists():
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(snap_path_str, target)
            if target.exists():
                rel_str = str(target.relative_to(self.workspace))
                self.file_mtimes[rel_str] = target.stat().st_mtime_ns
            return True
        return False

    @staticmethod
    def get_diff_preview(snap_path: str, current_path: str) -> str:
        if not snap_path or not os.path.exists(snap_path):
            if os.path.exists(current_path):
                try:
                    with open(current_path, "r", encoding="utf-8", errors="replace") as f:
                        lines = [next(f, "") for _ in range(35)]
                    return "[会话期间新建文件 - 前 35 行内容预览]:\n" + "".join(lines)
                except Exception:
                    pass
            return "(新建文件已被删除)"
        if not os.path.exists(current_path):
            return "⚠️ 当前文件已被 Agent 删除！点击顶部【⏪ 回退上一版】或【⏮ 还原基线】可立即恢复该文件。"
        try:
            with open(snap_path, "r", encoding="utf-8", errors="replace") as f1:
                old_lines = f1.readlines()
            with open(current_path, "r", encoding="utf-8", errors="replace") as f2:
                new_lines = f2.readlines()
            diff = list(difflib.unified_diff(old_lines, new_lines, fromfile="快照版本", tofile="当前工作区", n=2))
            if not diff:
                return "✅ 当前文件内容与对比快照完全一致（无实质文本行差异）。"
            return "".join(diff[:60])
        except Exception as e:
            return f"读取 Diff 失败: {e}"


# ============================================================================
# Tkinter 深色 GUI 模式 (支持双击任意行直接弹出独立监控与操控窗口)
# ============================================================================
def run_gui_mode(args):
    import tkinter as tk
    from tkinter import ttk, messagebox

    inspector = LinuxProcInspector(extra_names=args.extra_watch.split(",") if args.extra_watch else None)
    snap_mgr = WorkspaceSnapshotManager(args.workspace)
    baseline_count = snap_mgr.initialize_baseline()

    root = tk.Tk()
    root.title("🛡️ AI Agent 全栈行为感知与安全哨兵舱 (Agent Sentinel) v8.0 (Linux GUI 旗舰版)")
    root.geometry("1220x720")
    root.configure(bg="#0B0F19")
    root.attributes("-topmost", True)

    style = ttk.Style()
    style.theme_use("clam")
    style.configure("Treeview", background="#0F172A", foreground="#E2E8F0", fieldbackground="#0F172A", rowheight=26, font=("DejaVu Sans Mono", 10))
    style.configure("Treeview.Heading", background="#1E293B", foreground="#94A3B8", font=("DejaVu Sans", 10, "bold"))
    style.map("Treeview", background=[("selected", "#1D4ED8")], foreground=[("selected", "#FFFFFF")])

    state = {
        "active_pids": {},
        "records_by_key": {},
        "file_records": {},
        "open_popups": {},
        "agent_failures": {},
        "known_agents": set(),
        "latest_record": None,
        "total_captured": 0,
        "file_changes": 0,
        "tick": 0,
    }

    for entry in os.listdir("/proc"):
        if entry.isdigit():
            state["active_pids"][int(entry)] = {"pre_existing": True}

    # 顶部状态栏
    top_bar = tk.Frame(root, bg="#1E293B", padx=10, pady=6)
    top_bar.pack(fill=tk.X, padx=10, pady=(10, 4))

    lbl_status = tk.Label(top_bar, text="🟢 四维哨兵待命中", bg="#1E293B", fg="#10B981", font=("DejaVu Sans", 11, "bold"))
    lbl_status.pack(side=tk.LEFT)

    lbl_stats = tk.Label(top_bar, text=f"  |  受保护基线文件: {baseline_count}  |  活跃进程: 0  |  累计捕获: 0", bg="#1E293B", fg="#CBD5E1", font=("DejaVu Sans", 10))
    lbl_stats.pack(side=tk.LEFT, padx=8)

    var_auto_freeze = tk.BooleanVar(value=args.auto_freeze)
    var_circuit = tk.BooleanVar(value=True)
    var_topmost = tk.BooleanVar(value=True)

    tk.Checkbutton(
        top_bar, text="📌 置顶", variable=var_topmost, bg="#1E293B", fg="#CBD5E1", selectcolor="#0F172A",
        command=lambda: root.attributes("-topmost", var_topmost.get())
    ).pack(side=tk.RIGHT, padx=6)
    tk.Checkbutton(
        top_bar, text="🔴 高危自动SIGSTOP冻结树", variable=var_auto_freeze, bg="#1E293B", fg="#FCA5A5", selectcolor="#0F172A"
    ).pack(side=tk.RIGHT, padx=6)
    tk.Checkbutton(
        top_bar, text="⚡ 按Agent独立熔断", variable=var_circuit, bg="#1E293B", fg="#FBBF24", selectcolor="#0F172A"
    ).pack(side=tk.RIGHT, padx=6)

    # 工具栏
    tool_bar = tk.Frame(root, bg="#151E2E", padx=8, pady=5)
    tool_bar.pack(fill=tk.X, padx=10, pady=4)

    tk.Label(tool_bar, text="🔍 过滤:", bg="#151E2E", fg="#94A3B8").pack(side=tk.LEFT, padx=4)
    var_filter = tk.StringVar(value=args.filter_agent)
    ent_filter = tk.Entry(tool_bar, textvariable=var_filter, bg="#0B0F19", fg="#F3F4F6", insertbackground="#FFFFFF", width=22)
    ent_filter.pack(side=tk.LEFT, padx=4)

    # 主标签页
    notebook = ttk.Notebook(root)
    notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=4)

    tab_proc = tk.Frame(notebook, bg="#0B0F19")
    tab_file = tk.Frame(notebook, bg="#0B0F19")
    notebook.add(tab_proc, text="🚀 1. 多Agent并发命令流 (💡直接双击任意行跳出独立监控窗)")
    notebook.add(tab_file, text="📝 2. 工作区文件篡改哨兵 & 双轨时光机 (双击跳出独立Diff窗)")

    cols_proc = ("time", "agent", "state", "risk", "proc", "cwd", "cmd", "result", "mem_cpu", "net")
    tree_proc = ttk.Treeview(tab_proc, columns=cols_proc, show="headings", selectmode="browse")
    headers_proc = [
        ("time", "时间", 85), ("agent", "所属 Agent 实例", 130), ("state", "状态", 95),
        ("risk", "风险", 70), ("proc", "进程 (PID)", 115), ("cwd", "工作目录 (CWD)", 130),
        ("cmd", "执行命令 / 自动解码摘要 (双击此行跳出独立窗口)", 320),
        ("result", "耗时 & 退出状态", 115), ("mem_cpu", "内存 & CPU", 110), ("net", "双栈端口/外联", 105)
    ]
    for cid, text, w in headers_proc:
        tree_proc.heading(cid, text=text)
        tree_proc.column(cid, width=w, stretch=(cid == "cmd"))
    tree_proc.pack(fill=tk.BOTH, expand=True)

    cols_file = ("time", "badge", "trigger", "rel", "status", "full")
    tree_file = ttk.Treeview(tab_file, columns=cols_file, show="headings", selectmode="browse")
    for cid, text, w in [
        ("time", "时间", 90), ("badge", "动作类型", 95), ("trigger", "归因触发进程", 180),
        ("rel", "相对路径", 260), ("status", "双轨微快照状态", 220), ("full", "完整路径", 320)
    ]:
        tree_file.heading(cid, text=text)
        tree_file.column(cid, width=w, stretch=(cid == "full"))
    tree_file.pack(fill=tk.BOTH, expand=True)

    # 底部快速预览栏
    bottom_frame = tk.Frame(root, bg="#0F172A", height=185)
    bottom_frame.pack(fill=tk.X, padx=10, pady=(4, 10))
    tk.Label(
        bottom_frame,
        text="🔎 快速预览栏 (💡 在上方表格【直接双击任意行】或按【Enter】即可跳出独立窗口单独查看并操控该命令，无需暂停后台流)",
        bg="#0F172A", fg="#60A5FA", anchor="w", font=("DejaVu Sans", 9, "bold")
    ).pack(fill=tk.X, padx=6, pady=2)
    txt_detail = tk.Text(bottom_frame, height=9, bg="#0B0F19", fg="#E2E8F0", font=("DejaVu Sans Mono", 9), wrap=tk.WORD)
    txt_detail.pack(fill=tk.BOTH, expand=True, padx=6, pady=4)

    def format_record_detail(rec: dict) -> str:
        lines = [
            f"【所属 Agent】 {rec['agent']}   |   【进程标识】 {rec['proc_display']}   |   【启动时间】 {rec['time']}",
            f"【当前状态】   {rec['state']}   |   【耗时结果】 {rec['result']}   |   【内存/CPU】 {rec['mem_cpu']}",
            f"【风险判定】   {rec['risk_badge']} — {rec['risk_reason']}",
            f"【调用族谱】   {rec['ancestry']}",
            f"【工作目录】   {rec['cwd_full']}",
            f"【双栈端口】   {rec['net'] or '无端口监听或外联'}",
            f"【派生子进程】 {', '.join(rec['children']) if rec['children'] else '无派生子进程'}",
            f"【关联文件流】 {', '.join(rec['touched_files']) if rec['touched_files'] else '运行期间暂未触发工作区文件修改'}",
            "",
            "==================== 完整命令行 (/proc/<pid>/cmdline) ====================",
            rec["full_cmd"],
        ]
        if rec["decoded"]:
            lines.extend(["", "==================== 自动解码与剥壳明文 ====================", rec["decoded"]])
        return "\n".join(lines)

    def open_popout_inspector(key: str, is_file: bool = False):
        if key in state["open_popups"]:
            win_info = state["open_popups"][key]
            try:
                win_info["win"].deiconify()
                win_info["win"].lift()
                return
            except Exception:
                del state["open_popups"][key]

        pop = tk.Toplevel(root)
        pop.geometry("680x480")
        pop.configure(bg="#0B0F19")
        pop.attributes("-topmost", True)

        hdr_frame = tk.Frame(pop, bg="#1E293B", padx=10, pady=6)
        hdr_frame.pack(fill=tk.X, padx=8, pady=(8, 4))
        lbl_pop_title = tk.Label(hdr_frame, text="单命令独立监控台", bg="#1E293B", fg="#38BDF8", font=("DejaVu Sans", 11, "bold"), anchor="w")
        lbl_pop_title.pack(fill=tk.X)
        lbl_pop_banner = tk.Label(hdr_frame, text="实时状态同步中...", bg="#1E293B", fg="#A7F3D0", font=("DejaVu Sans", 9), anchor="w")
        lbl_pop_banner.pack(fill=tk.X, pady=(2, 0))

        btn_bar = tk.Frame(pop, bg="#151E2E", padx=6, pady=4)
        btn_bar.pack(fill=tk.X, padx=8, pady=4)

        txt_pop = tk.Text(pop, bg="#0F172A", fg="#E2E8F0", font=("DejaVu Sans Mono", 10), wrap=tk.WORD)
        txt_pop.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0, 8))

        if not is_file and key in state["records_by_key"]:
            rec = state["records_by_key"][key]
            pop.title(f"🗗 独立监控: {rec['agent']} ➔ {rec['proc_display']}")
            lbl_pop_title.config(text=f"{rec['agent']}  ➔  {rec['proc_display']}")

            def do_suspend():
                if inspector.suspend_tree(rec["pid"]):
                    rec["state"] = "⏸ 树已冻结(SIGSTOP)"
                    refresh_pop()

            def do_resume():
                if inspector.resume_tree(rec["pid"]):
                    rec["state"] = "⚡ 运行中"
                    refresh_pop()

            def do_kill():
                if inspector.kill_tree(rec["pid"]):
                    rec["state"] = "🛑 已强杀(SIGKILL)"
                    refresh_pop()

            def do_open_cwd():
                if rec["cwd_full"] and os.path.isdir(rec["cwd_full"]):
                    subprocess.Popen(["xdg-open", rec["cwd_full"]], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            def do_export_md():
                out_md = Path.home() / f"Agent_Forensics_PID{rec['pid']}_{datetime.now().strftime('%H%M%S')}.md"
                out_md.write_text(f"# 🛡️ AI Agent 单命令执行取证报告 (Linux)\n\n```\n{format_record_detail(rec)}\n```\n", encoding="utf-8")
                messagebox.showinfo("导出成功", f"单命令取证报告已保存至：\n{out_md}", parent=pop)

            tk.Button(btn_bar, text="⏸ 冻结此命令树(SIGSTOP)", bg="#1E293B", fg="#FCD34D", command=do_suspend).pack(side=tk.LEFT, padx=3)
            tk.Button(btn_bar, text="▶ 恢复运行(SIGCONT)", bg="#1E293B", fg="#6EE7B7", command=do_resume).pack(side=tk.LEFT, padx=3)
            tk.Button(btn_bar, text="🛑 强杀此命令树(SIGKILL)", bg="#1E293B", fg="#FCA5A5", command=do_kill).pack(side=tk.LEFT, padx=3)
            tk.Button(btn_bar, text="📂 打开工作目录", bg="#1E293B", fg="#93C5FD", command=do_open_cwd).pack(side=tk.LEFT, padx=3)
            tk.Button(btn_bar, text="💾 导出取证单(.md)", bg="#1E293B", fg="#C084FC", command=do_export_md).pack(side=tk.LEFT, padx=3)

            def refresh_pop():
                lbl_pop_banner.config(text=f"{rec['state']}  |  耗时/结果: {rec['result']}  |  资源: {rec['mem_cpu']}  |  风险: {rec['risk_badge']}")
                txt_pop.delete("1.0", tk.END)
                txt_pop.insert(tk.END, format_record_detail(rec))

            refresh_pop()
            state["open_popups"][key] = {"win": pop, "refresh": refresh_pop}
        else:
            f_rec = state["file_records"].get(key, {})
            pop.title(f"🗗 文件变更对比: {f_rec.get('rel_path', '')}")
            lbl_pop_title.config(text=f"文件变更对比: {f_rec.get('rel_path', '')}")
            lbl_pop_banner.config(text=f"{f_rec.get('badge', '')}  |  归因: {f_rec.get('trigger', '')}")
            snap = f_rec.get("prev_path") or f_rec.get("base_path")
            txt_pop.insert(tk.END, WorkspaceSnapshotManager.get_diff_preview(snap, f_rec.get("full_path", "")))
            state["open_popups"][key] = {"win": pop, "refresh": lambda: None}

        pop.protocol("WM_DELETE_WINDOW", lambda: (state["open_popups"].pop(key, None), pop.destroy()))

    def on_proc_select(_event=None):
        sel = tree_proc.selection()
        if sel and sel[0] in state["records_by_key"]:
            txt_detail.delete("1.0", tk.END)
            txt_detail.insert(tk.END, format_record_detail(state["records_by_key"][sel[0]]))

    def on_file_select(_event=None):
        sel = tree_file.selection()
        if sel and sel[0] in state["file_records"]:
            f_rec = state["file_records"][sel[0]]
            snap = f_rec.get("prev_path") or f_rec.get("base_path")
            txt_detail.delete("1.0", tk.END)
            txt_detail.insert(tk.END, WorkspaceSnapshotManager.get_diff_preview(snap, f_rec.get("full_path", "")))

    tree_proc.bind("<<TreeviewSelect>>", on_proc_select)
    tree_file.bind("<<TreeviewSelect>>", on_file_select)
    tree_proc.bind("<Double-1>", lambda _e: open_popout_inspector(tree_proc.selection()[0], False) if tree_proc.selection() else None)
    tree_proc.bind("<Return>", lambda _e: open_popout_inspector(tree_proc.selection()[0], False) if tree_proc.selection() else None)
    tree_file.bind("<Double-1>", lambda _e: open_popout_inspector(tree_file.selection()[0], True) if tree_file.selection() else None)

    def rollback_selected(use_prev: bool):
        sel = tree_file.selection()
        if not sel or sel[0] not in state["file_records"]:
            messagebox.showinfo("提示", "请先在【2. 工作区文件篡改哨兵】中选中要回退的文件行。")
            return
        f_rec = state["file_records"][sel[0]]
        snap = (f_rec["prev_path"] if use_prev and f_rec["prev_path"] else f_rec["base_path"])
        if snap and snap_mgr.rollback_file(f_rec["full_path"], snap):
            f_rec["status"] = "✅ 已成功回退恢复"
            tree_file.item(sel[0], values=(f_rec["time_str"], f_rec["badge"], f_rec["trigger"], f_rec["rel_path"], f_rec["status"], f_rec["full_path"]))
            on_file_select()

    tk.Button(
        tool_bar, text="🗗 跳出独立窗口 (或双击任意行)", bg="#1E3A8A", fg="#38BDF8",
        command=lambda: open_popout_inspector(tree_proc.selection()[0], False) if tree_proc.selection() else None
    ).pack(side=tk.RIGHT, padx=3)
    tk.Button(tool_bar, text="⏮ 还原初始基线", bg="#1E293B", fg="#C084FC", command=lambda: rollback_selected(False)).pack(side=tk.RIGHT, padx=3)
    tk.Button(tool_bar, text="⏪ 回退上一版", bg="#1E293B", fg="#E879F9", command=lambda: rollback_selected(True)).pack(side=tk.RIGHT, padx=3)

    def poll_loop():
        state["tick"] += 1
        now = time.time()
        current_pids = set()

        for entry in os.listdir("/proc"):
            if not entry.isdigit():
                continue
            pid = int(entry)
            if pid == os.getpid():
                continue
            info = inspector.read_proc_stat_basic(pid)
            if not info:
                continue
            comm, proc_state, ppid, cpu_sec = info
            if comm.lower() not in inspector.watched:
                continue

            current_pids.add(pid)
            if pid not in state["active_pids"]:
                cmdline = inspector.read_proc_cmdline(pid) or f"[{comm}]"
                ancestry, agent_inst = inspector.get_ancestry_and_agent(ppid)
                kw = var_filter.get().strip()
                if kw and not re.search(kw, f"{agent_inst} {ancestry} {comm} {cmdline}", re.IGNORECASE):
                    state["active_pids"][pid] = {"pre_existing": True}
                    continue

                state["known_agents"].add(agent_inst)
                cwd_full = inspector.read_proc_cwd(pid)
                cwd_short = os.path.basename(cwd_full) if cwd_full else "(未知)"
                decoded = decode_command_payload(cmdline)
                risk = evaluate_command_risk(cmdline, decoded)
                rss_mb = inspector.read_proc_rss_mb(pid)
                net_str = inspector.get_tcp_summary_for_pid(pid)

                init_state = "⚡ 运行中"
                ag_fails = state["agent_failures"].get(agent_inst, 0)
                if (risk["score"] >= 3 and var_auto_freeze.get()) or (var_circuit.get() and ag_fails >= args.max_failures):
                    if inspector.suspend_tree(pid):
                        init_state = "⏸ 高危已冻结" if risk["score"] >= 3 else "⏸ 熔断已冻结"

                if ppid in state["active_pids"] and not state["active_pids"][ppid].get("pre_existing"):
                    parent_rec = state["active_pids"][ppid]["rec"]
                    parent_rec["children"].append(f"{comm}({pid})")

                key = f"PID_{pid}_{int(now * 1000)}"
                preview = f"🔓 {decoded.splitlines()[0][:110]}" if decoded else cmdline[:120]
                rec = {
                    "key": key,
                    "pid": pid,
                    "time": datetime.now().strftime("%H:%M:%S.%f")[:-3],
                    "agent": agent_inst,
                    "state": init_state,
                    "risk_badge": risk["badge"],
                    "risk_reason": risk["reason"],
                    "proc_display": f"{comm} ({pid})",
                    "ancestry": ancestry,
                    "cwd_short": cwd_short,
                    "cwd_full": cwd_full,
                    "cmd_preview": preview,
                    "full_cmd": cmdline,
                    "decoded": decoded,
                    "result": "运行中...",
                    "mem_cpu": f"{rss_mb}MB | CPU:{cpu_sec}s",
                    "net": net_str,
                    "start_ts": now,
                    "children": [],
                    "touched_files": [],
                }
                state["records_by_key"][key] = rec
                state["active_pids"][pid] = {"pre_existing": False, "rec": rec}
                state["latest_record"] = rec
                state["total_captured"] += 1

                tree_proc.insert("", 0, iid=key, values=(
                    rec["time"], rec["agent"], rec["state"], rec["risk_badge"],
                    rec["proc_display"], rec["cwd_short"], rec["cmd_preview"],
                    rec["result"], rec["mem_cpu"], rec["net"]
                ))
            else:
                entry_obj = state["active_pids"][pid]
                if not entry_obj.get("pre_existing") and (state["tick"] % 4 == 0):
                    rec = entry_obj["rec"]
                    elapsed = round(now - rec["start_ts"], 1)
                    rss_mb = inspector.read_proc_rss_mb(pid)
                    rec["result"] = f"{elapsed}s (运行中)"
                    rec["mem_cpu"] = f"{rss_mb}MB | CPU:{cpu_sec}s"
                    if not rec["net"] and elapsed > 0.4:
                        rec["net"] = inspector.get_tcp_summary_for_pid(pid)
                    tree_proc.item(rec["key"], values=(
                        rec["time"], rec["agent"], rec["state"], rec["risk_badge"],
                        rec["proc_display"], rec["cwd_short"], rec["cmd_preview"],
                        rec["result"], rec["mem_cpu"], rec["net"]
                    ))
                    if rec["key"] in state["open_popups"]:
                        state["open_popups"][rec["key"]]["refresh"]()

        # 处理已退出进程
        exited = [p for p in list(state["active_pids"].keys()) if p not in current_pids]
        for old_pid in exited:
            entry_obj = state["active_pids"].pop(old_pid)
            if not entry_obj.get("pre_existing"):
                rec = entry_obj["rec"]
                dur = round(now - rec["start_ts"], 2)
                rec["state"] = "✅ 已结束"
                rec["result"] = f"{dur}s"
                tree_proc.item(rec["key"], values=(
                    rec["time"], rec["agent"], rec["state"], rec["risk_badge"],
                    rec["proc_display"], rec["cwd_short"], rec["cmd_preview"],
                    rec["result"], rec["mem_cpu"], rec["net"]
                ))
                if rec["key"] in state["open_popups"]:
                    state["open_popups"][rec["key"]]["refresh"]()

        # 每 5 个 Tick 扫描一次工作区文件变更并执行因果关联
        if state["tick"] % 5 == 0:
            for fevt in snap_mgr.scan_changes():
                corr = state["latest_record"]
                trigger_str = "⚡ 宿主直接写入 (Node/Python API)"
                if corr and (now - corr["start_ts"] < 15.0):
                    trigger_str = f"{corr['agent']} ➔ {corr['proc_display']}"
                    corr["touched_files"].append(f"{fevt['badge']} {fevt['rel_path']}")
                    if corr["key"] in state["open_popups"]:
                        state["open_popups"][corr["key"]]["refresh"]()

                fevt["trigger"] = trigger_str
                fkey = f"FILE_{state['file_changes']}_{int(now * 1000)}"
                state["file_records"][fkey] = fevt
                state["file_changes"] += 1
                tree_file.insert("", 0, iid=fkey, values=(
                    fevt["time_str"], fevt["badge"], fevt["trigger"],
                    fevt["rel_path"], fevt["status"], fevt["full_path"]
                ))

        running_cnt = sum(1 for v in state["active_pids"].values() if not v.get("pre_existing"))
        lbl_status.config(
            text=f"⚡ 正在执行后台命令 ({running_cnt})" if running_cnt > 0 else "🟢 四维哨兵待命中",
            fg="#F59E0B" if running_cnt > 0 else "#10B981"
        )
        lbl_stats.config(
            text=f"  |  并发Agent: {len(state['known_agents'])}  |  活跃进程: {running_cnt}  |  累计命令: {state['total_captured']}  |  文件变更: {state['file_changes']}  |  已开独立窗: {len(state['open_popups'])}"
        )
        root.after(args.interval, poll_loop)

    root.after(args.interval, poll_loop)
    root.mainloop()


# ============================================================================
# CLI 终端交互模式 (适配无桌面 SSH / Docker / Server 环境)
# ============================================================================
def run_cli_mode(args):
    inspector = LinuxProcInspector(extra_names=args.extra_watch.split(",") if args.extra_watch else None)
    snap_mgr = WorkspaceSnapshotManager(args.workspace)
    base_cnt = snap_mgr.initialize_baseline()

    print("=" * 88)
    print(" 🛡️ AI Agent 全栈行为感知与安全哨兵舱 (Agent Sentinel) v8.0 (Linux CLI 极速模式)")
    print(f"    受保护工作区: {snap_mgr.workspace} (已建立 {base_cnt} 个文件双轨快照)")
    print("    按 Ctrl+C 退出监控")
    print("=" * 88)

    active_pids = {int(e): {"pre_existing": True} for e in os.listdir("/proc") if e.isdigit()}
    tick = 0

    try:
        while True:
            tick += 1
            now = time.time()
            current_pids = set()

            for entry in os.listdir("/proc"):
                if not entry.isdigit():
                    continue
                pid = int(entry)
                if pid == os.getpid():
                    continue
                info = inspector.read_proc_stat_basic(pid)
                if not info:
                    continue
                comm, _, ppid, cpu_sec = info
                if comm.lower() not in inspector.watched:
                    continue

                current_pids.add(pid)
                if pid not in active_pids:
                    cmdline = inspector.read_proc_cmdline(pid) or f"[{comm}]"
                    ancestry, agent_inst = inspector.get_ancestry_and_agent(ppid)
                    if args.filter_agent and not re.search(args.filter_agent, f"{agent_inst} {ancestry} {comm} {cmdline}", re.IGNORECASE):
                        active_pids[pid] = {"pre_existing": True}
                        continue

                    cwd_full = inspector.read_proc_cwd(pid)
                    decoded = decode_command_payload(cmdline)
                    risk = evaluate_command_risk(cmdline, decoded)
                    rss_mb = inspector.read_proc_rss_mb(pid)
                    net_str = inspector.get_tcp_summary_for_pid(pid)

                    ts_str = datetime.now().strftime("%H:%M:%S.%f")[:-3]
                    print(f"[{ts_str}] [{agent_inst}] {risk['badge']} 捕获: {comm} (PID: {pid}) | {rss_mb}MB | {net_str}")
                    print(f"  ├─ 调用族谱: {ancestry}")
                    if cwd_full:
                        print(f"  ├─ 工作目录: {cwd_full}")
                    print(f"  └─ 命令行  : {cmdline}")
                    if decoded:
                        print(f"  🔓 解码明文: {decoded}")

                    if risk["score"] >= 3 and args.auto_freeze:
                        if inspector.suspend_tree(pid):
                            print(f"  ⏸ [自动防御] 已通过 SIGSTOP 递归冻结高危进程树 (PID: {pid})！可执行 kill -CONT {pid} 放行。")

                    active_pids[pid] = {"pre_existing": False, "start_ts": now, "agent": agent_inst}

            exited = [p for p in list(active_pids.keys()) if p not in current_pids]
            for old_pid in exited:
                info_obj = active_pids.pop(old_pid)
                if not info_obj.get("pre_existing"):
                    dur = round(now - info_obj["start_ts"], 2)
                    ts_str = datetime.now().strftime("%H:%M:%S.%f")[:-3]
                    print(f"[{ts_str}] ⏹ [{info_obj['agent']}] 进程结束 (PID: {old_pid}) | 耗时: {dur}s\n")

            if tick % 5 == 0:
                for fevt in snap_mgr.scan_changes():
                    print(f"[{fevt['time_str']}] 📝 [文件哨兵 - {fevt['badge']}] {fevt['rel_path']} ({fevt['status']})")

            time.sleep(args.interval / 1000.0)
    except KeyboardInterrupt:
        print("\n⏹ 监控已安全退出。")


def main():
    parser = argparse.ArgumentParser(description="AI Agent 全栈行为感知与安全哨兵舱 (Agent Sentinel) v8.0 (Linux 独立版)")
    parser.add_argument("-w", "--workspace", default=os.getcwd(), help="受保护的工作区路径（默认当前目录）")
    parser.add_argument("-m", "--mode", choices=["auto", "gui", "cli"], default="auto", help="运行模式：auto / gui / cli")
    parser.add_argument("-i", "--interval", type=int, default=120, help="采样间隔毫秒数（默认 120ms）")
    parser.add_argument("-f", "--filter-agent", default="", help="过滤特定 Agent 或命令的正则表达式")
    parser.add_argument("-e", "--extra-watch", default="", help="额外监控的二进制名称（逗号分隔）")
    parser.add_argument("--no-auto-freeze", dest="auto_freeze", action="store_false", help="关闭高危指令自动 SIGSTOP 冻结")
    parser.set_defaults(auto_freeze=True)
    parser.add_argument("--max-failures", type=int, default=5, help="单 Agent 连续报错熔断阈值")
    args = parser.parse_args()

    has_display = bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))
    if args.mode == "cli" or (args.mode == "auto" and not has_display):
        run_cli_mode(args)
    else:
        try:
            import tkinter  # noqa: F401
            run_gui_mode(args)
        except Exception:
            print("⚠️ 当前环境未安装 python3-tk 或无图形界面，已自动切换至 CLI 终端模式。")
            run_cli_mode(args)


if __name__ == "__main__":
    main()
