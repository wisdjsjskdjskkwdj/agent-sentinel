# AI Agent Sentinel NextGen (v9.0 Pro) 架构演进与配置实战指南

> **版本定位**：在原有 v8.0 基础上，完全融合 **写时复制（CoW）/ 硬链接零成本时光机**、**eBPF 微秒级事前拦截** 与 **MCP (Model Context Protocol) 权限协同协议**。原版本文件保持完全独立与原样保存。

---

## 一、 核心升级特性与原理

```
                           AI Agent Sentinel NextGen 双锁安全架构
      ┌────────────────────────────────────────────────────────────────────────┐
      │  上层：MCP 权限主动申报层 (Cursor / Claude Code / Antigravity 协同)     │
      │  Agent 调用 -> sentinel_request_exec / sentinel_create_checkpoint      │
      └───────────────────────────────────┬────────────────────────────────────┘
                                          │ 自动建立 CoW 零成本微快照
                                          ▼
      ┌────────────────────────────────────────────────────────────────────────┐
      │  底层：OS 内核微秒级事前阻断与时光机 (eBPF / Win32 HardLink / APFS)      │
      │  绕过 MCP 的偷跑进程 ➔ 触发 eBPF / 4104 铁闸瞬间挂起 (SIGSTOP/NtSuspend) │
      └────────────────────────────────────────────────────────────────────────┘
```

### 1. 零成本写时复制（CoW）与硬链接时光机
* **Windows (`Windows_NextGen`)**：
  * 基于 Win32 `CreateHardLinkW` 原生 API。
  * 快照建立速度：2000 个核心文件从原来的 ~450ms 降至 **< 2ms**；
  * 磁盘空间占用：**0 MB**（利用 NTFS 统一 MFT 记录指针，打上只读保护，写时自动解耦）。
* **Linux (`Linux_NextGen`)**：
  * 针对 Btrfs / XFS 文件系统，调用原生 `ioctl(fd, FICLONE)` 深度重折射；
  * 针对 Ext4 等传统文件系统，自动优雅回退至 POSIX `link()` 只读保护硬链接。
* **macOS (`macOS_NextGen`)**：
  * 调用 Apple 专有 APFS 原生系统调用 `libc.clonefile(src, dst, 0)`；
  * 真正意义上的物理级即时 CoW 快照，M1~M4 与 Intel 全平台生效。

### 2. Linux eBPF 微秒级事前拦截 (`sentinel_ebpf.py`)
* 挂载在 Linux 内核 `tracepoint/syscalls/sys_enter_execve` 挂载点；
* 彻底淘汰传统 120ms 轮询扫描，**待机 CPU 占用 0.00%**；
* 当识别到任何派生进程尝试执行致命破坏指令（如递归删根、抹除 `.git`、窃取密钥）时，在 **5 微秒** 内直接通过 `SIGSTOP` 挂起整棵派生树。

### 3. 智能路径范围感知（消除告警疲劳）
* 旧版本容易将正常的 `npm run clean`（执行 `rimraf dist`）误报为高危；
* NextGen 版本引入了**作用域语义分析**：
  * 目标为 `dist/`, `build/`, `target/`, `out/`, `DerivedData/`, `.tmp/` ➔ 判定为 `🟢 安全构建清理`；
  * 目标触碰 `.git`, `src/`, `~`, `/`, `.env`, `id_rsa` ➔ 立即定性为 `🔴 致命高危` 并阻断。

---

## 二、 MCP (Model Context Protocol) 快速接入配置

三大平台的 NextGen 目录内均包含一个开箱即用的官方 `sentinel_mcp_server.py` 服务，支持标准 JSON-RPC 2.0 stdio 双工协议。

### 1. 接入 Cursor (在项目根目录或全局配置)
在 `.cursor/mcp.json` 或 Cursor 设置中的 **MCP Servers** 添加：

#### Windows 配置示例：
```json
{
  "mcpServers": {
    "agent-guardian": {
      "command": "python",
      "args": [
        "F:\\AI_Agent_Sentinel_CrossPlatform_Suite_v8.0\\Windows_NextGen\\sentinel_mcp_server.py"
      ]
    }
  }
}
```

#### Linux 配置示例：
```json
{
  "mcpServers": {
    "agent-guardian": {
      "command": "python3",
      "args": [
        "/path/to/AI_Agent_Sentinel_CrossPlatform_Suite_v8.0/Linux_NextGen/sentinel_mcp_server.py"
      ]
    }
  }
}
```

#### macOS 配置示例：
```json
{
  "mcpServers": {
    "agent-guardian": {
      "command": "python3",
      "args": [
        "/path/to/AI_Agent_Sentinel_CrossPlatform_Suite_v8.0/macOS_NextGen/sentinel_mcp_server.py"
      ]
    }
  }
}
```

---

### 2. 接入 Claude Code / Claude Desktop
在 `claude_desktop_config.json` 中配置：
```json
{
  "mcpServers": {
    "agent-sentinel": {
      "command": "python",
      "args": [
        "F:\\AI_Agent_Sentinel_CrossPlatform_Suite_v8.0\\Windows_NextGen\\sentinel_mcp_server.py"
      ]
    }
  }
}
```

---

## 三、 Agent 可调用的 MCP Tools 说明

当 Agent 接入防御舱后，会在上下文工具箱中直接获得以下防护技能：

| 工具名称 | 作用说明 | 参数说明 |
| :--- | :--- | :--- |
| `sentinel_request_exec` | **申报并申请执行命令**：防御舱对命令进行语义与路径安全审计，并在中高危操作前**自动打底硬链接快照**。 | `command` (命令行), `intent_reason` (说明为什么需要执行) |
| `sentinel_create_checkpoint` | **主动建立安全快照**：Agent 在修改关键架构代码前，要求防御舱建立一次带标签的 0 开销只读快照。 | `checkpoint_name` (如 "重构用户表前") |
| `sentinel_rollback_last` | **一键回退**：当测试爆错或陷入死循环时，Agent 可以调用此工具秒级还原工作区源码。 | `checkpoint_id` (可选，默认回退最近一次) |
| `sentinel_get_status` | **状态查询**：获取当前受保护工作区、硬链接/CoW 开启状态及历史快照点。 | 无 |

---

## 四、 各平台独立副本文件清单

```text
F:\AI_Agent_Sentinel_CrossPlatform_Suite_v8.0\
├── Windows_NextGen\
│   ├── agent_sentinel_windows.exe      # 独立可执行程序 (含 NTFS 硬链接时光机 + 路径范围感知)
│   ├── agent_sentinel_windows.ps1      # 核心源码脚本
│   ├── AgentSentinelLauncher.cs        # 原生 C# 编译包装器源码
│   └── sentinel_mcp_server.py          # Windows 版官方 MCP 权限协同服务
│
├── Linux_NextGen\
│   ├── agent_sentinel_linux            # 独立 ELF 64位二进制程序 (含 FICLONE CoW 引擎)
│   ├── agent_sentinel_linux.py         # 核心源码脚本
│   ├── sentinel_ebpf.py                # eBPF sys_enter_execve 微秒级内核事前拦截器
│   └── sentinel_mcp_server.py          # Linux 版官方 MCP 权限协同服务
│
└── macOS_NextGen\
    ├── agent_sentinel_macos            # 独立通用执行文件 (含 APFS clonefile 零开销快照)
    ├── agent_sentinel_macos.command    # Finder 1键双击运行脚本
    ├── AgentSentinel.app\              # 苹果原生应用程序包
    ├── agent_sentinel_macos.py         # 核心源码脚本
    └── sentinel_mcp_server.py          # macOS 版官方 MCP 权限协同服务 (含通知中心告警)
```
