# 📖 Agent Sentinel (全栈行为感知与安全哨兵舱) 官方操作与实战手册

> **项目名称**：Agent Sentinel (前称 AI Agent Sentinel)  
> **核心定位**：专为自动化 AI 编程 Agent（Cursor, Claude Code, Antigravity, AutoGPT 等）设计的跨平台全栈行为透视、零开销写时快照时光机与内核级安全防御系统。  
> **设计哲学**：**“感知但不越权，保护但不替人裁决”**。

---

## 目录
1. [系统架构与双版本说明](#1-系统架构与双版本说明)
2. [HUD 监控舱界面与四维感知详解](#2-hud-监控舱界面与四维感知详解)
3. [Windows 平台快速上手](#3-windows-平台快速上手)
4. [Linux 平台与服务器无头模式上手](#4-linux-平台与服务器无头模式上手)
5. [macOS 平台快速上手](#5-macos-平台快速上手)
6. [零成本写时复制（CoW）时光机与回滚实战](#6-零成本写时复制cow时光机与回滚实战)
7. [Linux eBPF 内核微秒事前拦截实战](#7-linux-ebpf-内核微秒事前拦截实战)
8. [MCP (Model Context Protocol) 接入实战](#8-mcp-model-context-protocol-接入实战)
9. [命令行参数与配置完全参考](#9-命令行参数与配置完全参考)
10. [常见问题与故障排查 (FAQ)](#10-常见问题与故障排查-faq)

---

## 1. 系统架构与双版本说明

为了兼顾“开箱即用”与“极致内核性能”，本项目提供两个独立版本分支：

```
agent-sentinel/
├── 📁 Windows/                # 【v8.0 经典版】独立 EXE 启动器 + WPF 暗黑极客 HUD
├── 📁 Linux/                  # 【v8.0 经典版】独立编译 ELF 64位二进制 + GUI/CLI 双模自适应
├── 📁 macOS/                  # 【v8.0 经典版】macOS 应用程序包 (AgentSentinel.app) + .command 脚本
│
├── 📁 Windows_NextGen/        # 【NextGen 进化版】+ NTFS HardLink 零成本时光机 + MCP Server
├── 📁 Linux_NextGen/          # 【NextGen 进化版】+ Linux eBPF 探针 + Btrfs/XFS CoW + MCP Server
├── 📁 macOS_NextGen/          # 【NextGen 进化版】+ Apple APFS clonefile() CoW + MCP Server
│
├── 📄 MANUAL.md               # 本操作手册
├── 📄 NEXTGEN_MCP_AND_COW_GUIDE.md  # NextGen 深度技术进阶
└── 📄 README.md               # 项目主页与快速上手
```

* **v8.0 经典版**：专注于用户态进程追踪与安全审计，自包含且零外部环境依赖，双击即可直接运行。
* **NextGen 进化版**：在经典版基础上，引入了操作系统底层写时复制（CoW）、Linux 内核级 eBPF 探针，以及全套 MCP 权限协议，为现代 AI 编程助手提供双向主动协同。

---

## 2. HUD 监控舱界面与四维感知详解

### 顶部状态面板与熔断控制
* **状态指示灯**：`🟢 四维哨兵待命中`，实时展示当前并发 Agent 数量、活跃进程、累计执行命令总数、捕获文件变更数及已打开的独立详情窗数。
* **按 Agent 独立熔断**：防止某一个 Agent 陷入报错重试的死循环耗尽 Token 或系统资源。
* **高危自动冻结树**：默认开启。当检测到可能摧毁工程的命令时，自动通过系统底层挂起信号（Windows `NtSuspendProcess` / Linux `SIGSTOP`）将整棵进程树挂起，而非强杀，方便人工核查。

### 四大核心监控选项卡（Tabs）

#### Tab 1：多 Agent 并发命令流 (按 Enter / 双击查看单命令独立窗)
* 记录每个命令的启动时间、所属 Agent（自动归因 Cursor / Claude Code / Antigravity 等）、当前状态（运行中 / 已结束）、风险评级、进程 PID、耗时、退出码以及内存/CPU 遥测。
* **双击任意行**：立即跳出针对该命令的专属独立取证窗口，查看其完整的命令行、调用族谱链条（如 `explorer -> Antigravity -> powershell -> python`）及其实际关联修改的文件。

#### Tab 2：文件篡改哨兵 & 双轨时光机
* 实时监控受保护工作区内的文件创建、内容修改与删除。
* 自动记录文件的基线版本（初始状态）与上一版本（修改前瞬间）。
* **快速预览栏**：自动生成 `unified_diff` 差异对比，直观呈现新旧代码的增删改动（绿色标注新增、红色标注删除）。
* **一键回滚**：
  * **`[⏪ 回退上一版]`**：瞬间撤销本次修改，退回到修改前的版本。
  * **`[⏮️ 还原基线]`**：彻底还原回监控启动时的初始状态。若是新创建的文件，则提示是否安全清理。

#### Tab 3：常驻 Shell 内部指令嗅探 (Windows 独有)
* 深度解析常驻终端（如父进程长期不退出的 PowerShell 宿主），通过底层事件感知嗅探其内部执行的代码块历史与高危脚本。

#### Tab 4：孤儿僵尸进程 & 死锁猎手
* **孤儿进程清理**：扫描父进程已退出但仍在后台默默消耗 CPU/内存或霸占端口的残留子进程（如残留的 Vite、Webpack、Python 守护进程）。
* **死锁解除**：自动检测并清理 `.git/index.lock` 等因 Agent 意外中断导致的 Git 索引死锁，一键恢复工作区。

---

## 3. Windows 平台快速上手

### 运行方式
进入 `Windows/` 或 `Windows_NextGen/` 目录：
1. **图形界面直启**：直接双击 `agent_sentinel_windows.exe`。
2. **命令行指定受保护目录**：
   ```cmd
   agent_sentinel_windows.exe -Workspace "D:\Projects\my-awesome-app"
   ```
3. **PowerShell 脚本直启**：
   ```powershell
   powershell.exe -ExecutionPolicy Bypass -File .\agent_sentinel_windows.ps1 -Workspace "D:\Projects\my-awesome-app"
   ```

---

## 4. Linux 平台与服务器无头模式上手

### 运行方式
进入 `Linux/` 或 `Linux_NextGen/` 目录：
```bash
chmod +x agent_sentinel_linux
```

1. **桌面环境（带显示器/X11/Wayland）**：
   ```bash
   ./agent_sentinel_linux --workspace /data/my_project
   ```
   程序会自动启动高颜值 Tkinter 深色 GUI 悬浮舱。

2. **服务器无头模式（SSH 远程 / Docker 容器 / CI/CD 流水线）**：
   当检测到没有图形桌面时，程序会自动无缝降级为终端彩色实时流模式（CLI）：
   ```bash
   ./agent_sentinel_linux -m cli -w /data/my_project
   ```

3. **后台守护运行**：
   ```bash
   nohup ./agent_sentinel_linux -m cli -w /data/my_project > sentinel.log 2>&1 &
   ```

---

## 5. macOS 平台快速上手

### 运行方式
进入 `macOS/` 或 `macOS_NextGen/` 目录：
1. **图形应用**：直接双击 `AgentSentinel.app`。
2. **终端启动脚本**：双击 `agent_sentinel_macos.command`。
3. **命令行运行**：
   ```bash
   ./agent_sentinel_macos --workspace ~/Developer/my_project
   ```

---

## 6. 零成本写时复制（CoW）时光机与回滚实战

在 `Windows_NextGen`、`Linux_NextGen` 和 `macOS_NextGen` 中，我们集成了操作系统底层写时复制技术：

* **Windows NTFS**：基于 `CreateHardLinkW`，指向同一个物理数据块，打上只读保护。快照耗时 **< 2ms**，**不占任何额外硬盘空间**。
* **Linux**：调用 `ioctl(FICLONE)` 原生重折射（Btrfs/XFS），或安全硬链接。
* **macOS**：调用 Apple 专有 APFS 原生系统调用 `clonefile()`。

### 回滚操作演示：
1. Agent 在工作区修改了 `src/index.js`；
2. 切换到界面的 **【2. 文件篡改哨兵】** 页面；
3. 选中 `src/index.js`，点击顶部的 **`[⏪ 回退上一版]`**；
4. 磁盘上的文件立即被原子替换恢复，修改彻底撤销。

---

## 7. Linux eBPF 内核微秒事前拦截实战

在 `Linux_NextGen` 目录下，附带了内核级探针 `sentinel_ebpf.py`：

```bash
cd Linux_NextGen
sudo python3 sentinel_ebpf.py
```

* **运行机制**：探针挂载在 Linux 内核 `tracepoint/syscalls/sys_enter_execve` 上。
* **拦截性能**：在命令执行前 **5 微秒** 内捕获。如果命令包含致命摧毁特征（如针对根目录的递归清理或窃取凭证），探针直接向该进程发送 `SIGSTOP`，使其在执行第一行机器指令前被定格在内存中，CPU 待机开销为 **0.00%**。

---

## 8. MCP (Model Context Protocol) 接入实战

NextGen 版本内置了 `sentinel_mcp_server.py`，支持 Cursor、Claude Code、Antigravity 等主流工具。

### 在 Cursor / Claude Code 中配置
在您编辑器的 MCP 配置文件（如 `~/.cursor/mcp.json` 或 `claude_desktop_config.json`）中添加：

```json
{
  "mcpServers": {
    "agent-sentinel": {
      "command": "python",
      "args": [
        "F:/AI_Agent_Sentinel_CrossPlatform_Suite_v8.0/Windows_NextGen/sentinel_mcp_server.py"
      ]
    }
  }
}
```

### 提供的 MCP 工具清单
* `sentinel_create_checkpoint`：创建当前工作区的零成本微秒快照。
* `sentinel_rollback`：一键回退到指定快照或上一版本。
* `sentinel_request_exec`：安全执行命令，执行前自动建立隔离区防护。
* `sentinel_get_status`：查询当前工作区是否有孤儿进程、被锁文件或高危操作。

---

## 9. 命令行参数与配置完全参考

| 参数选项 | 全称 | 说明 | 默认值 |
| :--- | :--- | :--- | :--- |
| `-w` | `--workspace` | 受保护的工作区绝对路径 | 当前工作目录 |
| `-m` | `--mode` | 运行模式：`auto` (自适应) / `gui` (强制图形) / `cli` (强制终端) | `auto` |
| `-i` | `--interval` | 进程轮询与状态采样周期 (毫秒) | `120` ms |
| `-f` | `--filter-agent` | 正则过滤特定 Agent 名称或命令参数 | 空 (监控全部) |
| `--no-auto-freeze` | — | 关闭高危指令自动挂起冻结（仅记录与报警） | 开启自动挂起 |
| `--max-failures` | — | 单 Agent 连续报错熔断阈值（防 Token 死循环） | `5` 次 |

---

## 10. 常见问题与故障排查 (FAQ)

### Q1：为什么启动时提示“未检测到图形界面”？
* **解答**：这在 Linux SSH 终端或未配置 X11 转发的环境中是正常现象。哨兵舱会自动降级到彩色 CLI 终端模式，所有感知功能与安全拦截完全正常工作。

### Q2：高危自动冻结后，如何恢复被暂停的进程？
* **解答**：
  * 在 GUI 界面上：选中该行，点击顶部的 **`[▶ 恢复树]`** 按钮。
  * 在 Linux 命令行中：直接执行 `kill -CONT <PID>` 即可唤醒该进程。
  * 在 Windows 命令行中：调用 `Resume-ProcessTree -RootPid <PID>`。

### Q3：哨兵舱会影响我的编译速度或大幅占用 CPU 吗？
* **解答**：不会。系统采用事件驱动与增量差异计算，在空闲时 CPU 占用通常低于 0.1%。NextGen 的写时复制（CoW）技术在创建快照时仅做元数据指针映射，耗时小于 2 毫秒。
