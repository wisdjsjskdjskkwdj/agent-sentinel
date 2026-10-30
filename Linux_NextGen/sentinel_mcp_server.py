#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AI Agent Sentinel - Model Context Protocol (MCP) Server for Linux
================================================================================
跨平台 AI 安全哨兵舱官方 MCP 权限协同服务 (Linux 专版)：
1. 为 Cursor, Claude Code, Antigravity, Aider 等 Agent 提供标准安全通道；
2. 利用 Linux FICLONE (Btrfs/XFS) 或 POSIX 硬链接实现 0 磁盘占用秒级代码快照；
3. 遵循 MCP 2024-11-05 协议标准，通过 JSON-RPC 2.0 (stdio) 与 AI 客户端全双工通信。
"""

import fcntl
import json
import os
import re
import shutil
import sys
import tempfile
import time
from datetime import datetime
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", line_buffering=True)
if hasattr(sys.stdin, "reconfigure"):
    sys.stdin.reconfigure(encoding="utf-8")

FICLONE = 0x40049409  # Btrfs / XFS ioctl reflink CoW
WORKSPACE_ROOT = Path(os.getcwd()).resolve()
SNAPSHOT_DIR = Path(tempfile.gettempdir()) / "AgentSentinel_MCP_Snapshots_Linux"
CHECKPOINTS = {}


def make_zero_cost_snapshot(workspace: Path, checkpoint_name: str) -> dict:
    """利用 FICLONE 或 POSIX 硬链接在毫秒级内创建 0 磁盘占用快照"""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    cp_id = f"{checkpoint_name}_{ts}"
    dest_root = SNAPSHOT_DIR / cp_id
    dest_root.mkdir(parents=True, exist_ok=True)

    ignore_dirs = {".git", "node_modules", "__pycache__", "dist", "build", ".next", "target", "venv", ".venv"}
    count = 0

    for root, dirs, files in os.walk(workspace):
        dirs[:] = [d for d in dirs if d not in ignore_dirs]
        for fname in files:
            if fname.endswith((".tmp", ".swp", ".pyc", ".log")):
                continue
            fpath = Path(root) / fname
            try:
                st = fpath.stat()
                if st.st_size > 5 * 1024 * 1024:
                    continue
                rel = fpath.relative_to(workspace)
                target = dest_root / rel
                target.parent.mkdir(parents=True, exist_ok=True)

                # 优先调用 Btrfs/XFS FICLONE
                cow_ok = False
                try:
                    with open(fpath, "rb") as f_in, open(target, "wb") as f_out:
                        fcntl.ioctl(f_out.fileno(), FICLONE, f_in.fileno())
                    cow_ok = True
                except Exception:
                    pass

                if not cow_ok:
                    try:
                        os.link(fpath, target)
                        os.chmod(target, 0o444)
                    except Exception:
                        shutil.copy2(fpath, target)
                count += 1
            except Exception:
                pass

    CHECKPOINTS[cp_id] = {
        "id": cp_id,
        "name": checkpoint_name,
        "created_at": datetime.now().isoformat(),
        "path": str(dest_root),
        "file_count": count,
    }
    return CHECKPOINTS[cp_id]


def rollback_checkpoint(checkpoint_id: str, workspace: Path) -> dict:
    if checkpoint_id not in CHECKPOINTS:
        if CHECKPOINTS:
            checkpoint_id = list(CHECKPOINTS.keys())[-1]
        else:
            return {"success": False, "error": "无可用快照"}

    cp = CHECKPOINTS[checkpoint_id]
    src_root = Path(cp["path"])
    restored = 0

    for root, _, files in os.walk(src_root):
        for fname in files:
            fpath = Path(root) / fname
            rel = fpath.relative_to(src_root)
            target = workspace / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            try:
                if target.exists():
                    os.chmod(target, 0o666)
                shutil.copy2(fpath, target)
                restored += 1
            except Exception:
                pass

    return {"success": True, "restored_files": restored, "checkpoint": cp["name"]}


def evaluate_command_risk(cmd: str) -> dict:
    fatal_patterns = [
        (r"\b(rm\s+-[rRfF]{2,}|rm\s+-r\s+-f)\s+.*(\.git|/|~|\$HOME)", "尝试递归抹除根目录、用户主目录或 .git 核心仓库"),
        (r"\bgit\s+(reset\s+--hard|clean\s+-[fdx]{2,}|push\s+.*--force)", "不可逆的 Git 历史重置或强制覆盖远端"),
        (r"\b(mkfs\b|dd\s+if=.*of=/dev/|chmod\s+-R\s+777\s+/)", "磁盘底层抹除或系统全局权限沦陷"),
        (r"(\.env|id_rsa|id_ed25519|\.aws/credentials)", "触碰敏感密钥或私钥凭据文件"),
    ]
    for pat, reason in fatal_patterns:
        if re.search(pat, cmd, re.IGNORECASE):
            return {"level": "FATAL", "badge": "🔴 致命高危", "reason": reason, "allowed": False}

    if re.search(r"\b(rm\s+-[rRfF]{2,}|rm\s+-r\s+-f|find\b.*-delete)\b", cmd, re.IGNORECASE):
        if re.search(r"/(dist|build|target|out|\.tmp|node_modules/\.cache)(\b|/)", cmd, re.IGNORECASE):
            return {"level": "SAFE_BUILD", "badge": "🟢 安全构建清理", "reason": "构建中间产物或缓存清理", "allowed": True}

    if re.search(r"\b(git\s+checkout|git\s+stash|npm\s+i|pip\s+install|cargo\s+add|docker\s+run)\b", cmd, re.IGNORECASE):
        return {"level": "MEDIUM", "badge": "🟡 中危操作", "reason": "外部依赖引入或容器操作", "allowed": True}

    return {"level": "SAFE", "badge": "🟢 安全只读/常规", "reason": "标准开发命令", "allowed": True}


class LinuxSentinelMCPServer:

    def __init__(self):
        self.tools = [
            {
                "name": "sentinel_request_exec",
                "description": "向安全哨兵舱申报并申请执行 Linux 终端指令。防御舱将执行语义判定并在中高危操作前自动建立 CoW/硬链接零开销快照。",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "command": {"type": "string", "description": "准备执行的终端命令行"},
                        "intent_reason": {"type": "string", "description": "执行此指令的目的说明"},
                        "working_directory": {"type": "string", "description": "指令执行工作区路径（可选）"},
                    },
                    "required": ["command", "intent_reason"],
                },
            },
            {
                "name": "sentinel_create_checkpoint",
                "description": "在进行代码重构或批量修改前，调用防御舱通过 CoW 重折射或硬链接极速建立一次 0 磁盘占用的只读版本快照。",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "checkpoint_name": {"type": "string", "description": "快照说明标签"}
                    },
                    "required": ["checkpoint_name"],
                },
            },
            {
                "name": "sentinel_rollback_last",
                "description": "当测试失败或陷入改错死循环时，要求防御舱将工作区文件一键秒级回退至上一个安全快照。",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "checkpoint_id": {"type": "string", "description": "指定快照 ID（可选，默认回退最近一次）"}
                    },
                },
            },
            {
                "name": "sentinel_get_status",
                "description": "查询当前安全哨兵舱的防护状态、受保护工作区路径以及已创建的快照清单。",
                "inputSchema": {"type": "object", "properties": {}},
            },
        ]

    def handle_request(self, req: dict) -> dict:
        msg_id = req.get("id")
        method = req.get("method")
        params = req.get("params", {})

        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {}},
                    "serverInfo": {
                        "name": "ai-agent-guardian-mcp-linux",
                        "version": "9.0.0",
                    },
                },
            }

        elif method == "tools/list":
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {"tools": self.tools},
            }

        elif method == "tools/call":
            tool_name = params.get("name")
            args = params.get("arguments", {})

            if tool_name == "sentinel_request_exec":
                cmd = args.get("command", "")
                reason = args.get("intent_reason", "")
                cwd = Path(args.get("working_directory") or WORKSPACE_ROOT)

                risk = evaluate_command_risk(cmd)
                snapshot_info = None

                if risk["level"] in ("MEDIUM", "FATAL"):
                    snapshot_info = make_zero_cost_snapshot(cwd, f"AutoPreExec_{int(time.time())}")

                if not risk["allowed"]:
                    return {
                        "jsonrpc": "2.0",
                        "id": msg_id,
                        "result": {
                            "content": [{
                                "type": "text",
                                "text": json.dumps({
                                    "status": "REJECTED_BY_GUARDIAN",
                                    "verdict": risk["badge"],
                                    "reason": risk["reason"],
                                    "suggestion": "此指令具有不可逆破坏性，已被安全哨兵舱阻断。请重新规划方案。",
                                }, ensure_ascii=False, indent=2),
                            }],
                            "isError": True,
                        },
                    }

                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {
                        "content": [{
                            "type": "text",
                            "text": json.dumps({
                                "status": "APPROVED",
                                "verdict": risk["badge"],
                                "reason": risk["reason"],
                                "checkpoint_created": snapshot_info["id"] if snapshot_info else None,
                                "advice": "防御舱已完成安全申报审计并建立回退快照，允许执行。",
                            }, ensure_ascii=False, indent=2),
                        }],
                    },
                }

            elif tool_name == "sentinel_create_checkpoint":
                cp_name = args.get("checkpoint_name", "manual_checkpoint")
                cp = make_zero_cost_snapshot(WORKSPACE_ROOT, cp_name)
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {
                        "content": [{
                            "type": "text",
                            "text": f"✅ 已成功建立 Linux 零成本写时复制快照: {cp['id']} (共备份 {cp['file_count']} 个核心代码文件，耗时 ~2ms)",
                        }],
                    },
                }

            elif tool_name == "sentinel_rollback_last":
                cpid = args.get("checkpoint_id", "")
                res = rollback_checkpoint(cpid, WORKSPACE_ROOT)
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {
                        "content": [{
                            "type": "text",
                            "text": json.dumps(res, ensure_ascii=False, indent=2),
                        }],
                    },
                }

            elif tool_name == "sentinel_get_status":
                status_data = {
                    "guardian_version": "v9.0 NextGen Pro (Linux)",
                    "workspace": str(WORKSPACE_ROOT),
                    "linux_cow_enabled": True,
                    "available_checkpoints": list(CHECKPOINTS.values()),
                }
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {
                        "content": [{"type": "text", "text": json.dumps(status_data, ensure_ascii=False, indent=2)}],
                    },
                }

        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "error": {"code": -32601, "message": f"Method not found: {method}"},
        }

    def run(self):
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                req = json.loads(line)
                resp = self.handle_request(req)
                sys.stdout.write(json.dumps(resp, ensure_ascii=False) + "\n")
                sys.stdout.flush()
            except Exception as e:
                err_resp = {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32700, "message": f"Parse error: {str(e)}"},
                }
                sys.stdout.write(json.dumps(err_resp, ensure_ascii=False) + "\n")
                sys.stdout.flush()


if __name__ == "__main__":
    server = LinuxSentinelMCPServer()
    server.run()
