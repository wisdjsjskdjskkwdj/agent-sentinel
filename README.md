# 🛡️ AI Agent Sentinel Cross-Platform Suite
> **Cross-platform runtime observability, zero-cost CoW snapshot time-machine, and safety cockpit for AI Agents (Cursor, Claude Code, Antigravity).**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)]()
[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)]()
[![MCP](https://img.shields.io/badge/MCP-Protocol%20Ready-purple.svg)]()

> **核心哲学：“感知但不越权，保护但不替人裁决”**  
> 为自动化 AI Agent（如 Cursor、Claude Code、Antigravity、AutoGPT 等）提供全天候物理级进程追踪、零开销写时复制时光机、微秒级行为审计与双向 MCP 权限协同。

---

## 📌 项目架构：双版本设计

本项目同时提供两个独立的版本分支，满足不同场景下的安全与审计需求：

```
AI_Agent_Sentinel_CrossPlatform_Suite/
│
├── 📁 Windows/                # 【v8.0 经典版】Windows 原生独立可执行程序 (.exe / WPF / PS5.1)
├── 📁 Linux/                  # 【v8.0 经典版】Linux 独立编译 ELF 二进制程序 (PyInstaller / Tk)
├── 📁 macOS/                  # 【v8.0 经典版】macOS 独立应用程序包 (AgentSentinel.app / .command)
│
├── 📁 Windows_NextGen/        # 【NextGen 进化版】+ Win32 NTFS HardLink 零成本时光机 + MCP Server
├── 📁 Linux_NextGen/          # 【NextGen 进化版】+ eBPF 微秒级内核挂载 + Btrfs/XFS CoW + MCP Server
├── 📁 macOS_NextGen/          # 【NextGen 进化版】+ Apple APFS 原生 clonefile() CoW + MCP Server
│
├── 📄 NEXTGEN_MCP_AND_COW_GUIDE.md           # NextGen 与 MCP 深度集成技术指南
├── 📄 AI_Agent_Sentinel_CrossPlatform_Manual.pdf  # 官方架构设计与操作手册
└── 📄 README.md                              # 本说明文件
```

---

## 🚀 核心版本特性对比

| 核心维度 | 经典稳定版 (Classic v8.0) | 进化增强版 (NextGen) |
| :--- | :--- | :--- |
| **可执行分发** | **开箱即用**：独立 .exe / ELF 二进制 / .app 包 | **开箱即用**：独立二进制 + 扩展支持 |
| **文件时光机** | 全文快照比对，双轨版本归档 | **零空间消耗**：NTFS 硬链接 / APFS `clonefile` / Btrfs `FICLONE` |
| **内核事前阻断** | 进程树轮询（120ms）+ 挂起 API | **Linux eBPF 原生挂载**（微秒级响应，0% 待机占用） |
| **Agent 协议** | 纯被动式全栈流量/进程/文件探针 | **主动双向 MCP 协议**（支持 Cursor / Claude Code / Antigravity） |
| **告警疲劳控制** | 基于正则与命令特征评分 | **语义范围感知**（构建清理 `dist/` 放行，敏感配置 `.git` 拦截） |

---

## ⚡ 快速开始 (Quick Start)

### 1. Windows 平台
- **直接运行**：双击进入 `Windows/` 或 `Windows_NextGen/` 目录，双击 `agent_sentinel_windows.exe` 即可启动暗黑极客 WPF HUD 监控舱。
- **自定义工作区启动**：
  ```cmd
  agent_sentinel_windows.exe -Workspace "D:\YourProject"
  ```

### 2. Linux 平台
- **直接运行**：
  ```bash
  cd Linux_NextGen  # 或 cd Linux
  chmod +x agent_sentinel_linux
  ./agent_sentinel_linux --workspace /path/to/project
  ```
- **启动 eBPF 内核微秒探针 (可选，需 root)**：
  ```bash
  sudo python3 sentinel_ebpf.py
  ```

### 3. macOS 平台
- **直接运行**：
  - 双击 `macOS/AgentSentinel.app`，或双击 `agent_sentinel_macos.command`。
  - 命令行启动：
    ```bash
    ./macOS_NextGen/agent_sentinel_macos --workspace ~/my-project
    ```

---

## 🔌 MCP (Model Context Protocol) 接入

NextGen 版本原生附带 `sentinel_mcp_server.py`。您可以在 Cursor、Claude Code 或 Antigravity 等 AI 编程助手配置中一键添加：

```json
{
  "mcpServers": {
    "agent-sentinel": {
      "command": "python",
      "args": ["F:/AI_Agent_Sentinel_CrossPlatform_Suite_v8.0/Windows_NextGen/sentinel_mcp_server.py"]
    }
  }
}
```

Agent 在执行高危操作（如删除大型文件夹、批量重构）前，将主动通过 MCP 协议申报并自动获得一次微秒级零成本快照保护！

---

## 🛡️ 安全设计哲学

1. **监控但不越权**：默认绝不武断终止（Kill）任何 Agent 正在执行的代码，防止破坏正常运行中的复杂构建流程。
2. **保护但不替人裁决**：当检测到风险时，系统采用挂起暂停（Freeze / `NtSuspendProcess` / `SIGSTOP`）机制，并将最高裁决权交还给屏幕前的人类工程师（支持一键恢复或一键回滚）。
3. **可复制与自包含**：所有模块均已编译成平台原生可执行文件，不依赖特定 Python 虚拟环境即可跨机运行。

---

## 📄 开源许可证

本项目基于 [MIT License](LICENSE) 开源发布。
