<#
.SYNOPSIS
    AI Agent 全栈行为感知与安全哨兵舱 (Agent Sentinel) (Ultimate 终极完备版 v8.0 - 因果关联 & 智能独立弹窗版)
.DESCRIPTION
    本版本在先期深度思考与全局架构审视后，完成了最后 5 项关键闭环优化：
    1. 【进程 ➔ 文件改动 ➔ 内存脚本 因果时间轴关联引擎 (Causal Correlation Engine)】
       - 打破“看命令”与“看文件改动”的割裂：当某个后台命令正在运行时，工作区内发生的任何文件增删改或 4104 内存脚本块，
         都会自动按时间轴归因挂载到当前活跃的命令记录下（TouchedFilesText / LiveSubEventsText）；
       - 当你双击某条命令跳出独立窗口时，不仅能看到命令本身，还能直接看到“这条命令运行期间动了哪些文件、跑了哪些子进程”。
    2. 【独立监控窗防重与生命周期管理 + 内存/CPU 实时遥测 + 单命令 Markdown 取证导出】
       - 对同一条命令多次双击时，自动唤醒并置顶已打开的专属窗口，绝不重复弹出冗余窗口；所有子窗口随主窗口安全联动销毁；
       - 实时采集后台进程的物理内存占用 (MB) 与 CPU 时间，一眼识别内存泄漏或死循环进程；
       - 独立窗口内置【💾 导出此命令取证单 (.md)】与【📂 打开工作目录】，并支持在主表按 Enter / Space 键直接弹窗。
    3. 【带 2.5 秒移动感知的“智能瞄准防抖 (Smart Aim Stabilization)”】
       - 修复了“鼠标一直停在表格上发呆导致新命令永久不刷入”的边界死锁；
       - 仅当鼠标在表格内移动瞄准的 2.5 秒窗口期内锁定行位置（让你稳稳双击目标行而不被新行顶歪），鼠标静止满 2.5 秒或移出表格后自动无感合入新命令。
    4. 【多 Agent 通道隔离、C# INotifyPropertyChanged 零跳动更新、双栈 TCP 极速透视、双轨文件时光机全系就绪】
.PARAMETER WorkspacePath
    需要保护和监控文件变更的项目工作区路径（默认当前目录 $PWD）
.PARAMETER Mode
    运行模式：Auto (默认，有桌面则启动 GUI，否则自动降级 CLI)、GUI 或 CLI
.PARAMETER PollIntervalMs
    极速采样间隔（毫秒），默认 120ms
.PARAMETER FilterAgent
    可选：初始过滤关键字
.PARAMETER ExtraWatchNames
    可选：额外追加监控的进程名（逗号分隔）
.PARAMETER AutoFreezeHighRisk
    是否在捕获高危命令或触发死循环熔断时自动递归冻结进程树（默认开启）
.PARAMETER MaxConsecutiveFailures
    单个 Agent 实例的连续报错熔断阈值（默认 5 次）
#>

param(
    [string]$WorkspacePath = $PWD.Path,
    [ValidateSet("Auto", "GUI", "CLI")]
    [string]$Mode = "Auto",
    [int]$PollIntervalMs = 120,
    [string]$FilterAgent = "",
    [string]$ExtraWatchNames = "",
    [bool]$AutoFreezeHighRisk = $true,
    [int]$MaxConsecutiveFailures = 5
)

$ErrorActionPreference = "SilentlyContinue"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# ============================================================================
# 0. 运行环境、权限与 STA 线程公寓模式自适应检测
# ============================================================================
$Script:IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$Script:PSMajorVersion = $PSVersionTable.PSVersion.Major
$Script:IsInteractiveDesktop = [Environment]::UserInteractive

if ($Mode -ne "CLI" -and $Script:IsInteractiveDesktop) {
    if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne [System.Threading.ApartmentState]::STA) {
        $hostExe = (Get-Process -Id $PID).Path
        if (-not $hostExe) { $hostExe = if ($Script:PSMajorVersion -ge 6) { "pwsh.exe" } else { "powershell.exe" } }
        if ($MyInvocation.MyCommand.Path) {
            $relaunchArgs = @(
                "-NoProfile", "-STA", "-ExecutionPolicy", "Bypass",
                "-File", "`"$($MyInvocation.MyCommand.Path)`"",
                "-WorkspacePath", "`"$WorkspacePath`"",
                "-Mode", $Mode,
                "-PollIntervalMs", $PollIntervalMs,
                "-MaxConsecutiveFailures", $MaxConsecutiveFailures
            )
            if ($FilterAgent) { $relaunchArgs += @("-FilterAgent", "`"$FilterAgent`"") }
            if ($ExtraWatchNames) { $relaunchArgs += @("-ExtraWatchNames", "`"$ExtraWatchNames`"") }
            if (-not $AutoFreezeHighRisk) { $relaunchArgs += @("-AutoFreezeHighRisk:`$false") }
            Start-Process -FilePath $hostExe -ArgumentList $relaunchArgs -Wait
            exit
        } else {
            $Mode = "CLI"
        }
    }
} elseif (-not $Script:IsInteractiveDesktop) {
    $Mode = "CLI"
}

# ============================================================================
# 1. 底层 Win32 / NTAPI / 双栈 TCP + 因果关联响应式进程模型 (AgentProcessRecordV8)
# ============================================================================
if (-not ("SentinelNativeApiV8" -as [type])) {
    $NativeCode = @"
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;

public class AgentProcessRecordV8 : INotifyPropertyChanged {
    public event PropertyChangedEventHandler PropertyChanged;
    private void Notify(string prop) {
        var h = PropertyChanged;
        if (h != null) h(this, new PropertyChangedEventArgs(prop));
    }

    public string UniqueKey { get; set; }
    public uint Pid { get; set; }
    public string TimeStr { get; set; }
    public string AgentInstance { get; set; }
    public string RiskBadge { get; set; }
    public string RiskReason { get; set; }
    public string ProcessDisplay { get; set; }
    public string AncestryChain { get; set; }
    public string CwdDisplay { get; set; }
    public string CwdFull { get; set; }
    public string CommandPreview { get; set; }
    public string FullCommand { get; set; }
    public string DecodedText { get; set; }
    public DateTime StartTime { get; set; }

    private string _stateText;
    public string StateText {
        get { return _stateText; }
        set { if (_stateText != value) { _stateText = value; Notify("StateText"); Notify("LiveBannerText"); Notify("LiveDetailSummary"); } }
    }

    private bool _isSuspended;
    public bool IsSuspended {
        get { return _isSuspended; }
        set { if (_isSuspended != value) { _isSuspended = value; Notify("IsSuspended"); } }
    }

    private string _resultText;
    public string ResultText {
        get { return _resultText; }
        set { if (_resultText != value) { _resultText = value; Notify("ResultText"); Notify("LiveBannerText"); Notify("LiveDetailSummary"); } }
    }

    private string _resourceUsage = "采集中...";
    public string ResourceUsage {
        get { return _resourceUsage; }
        set { if (_resourceUsage != value) { _resourceUsage = value; Notify("ResourceUsage"); Notify("LiveBannerText"); Notify("LiveDetailSummary"); } }
    }

    private string _netSummary;
    public string NetSummary {
        get { return _netSummary; }
        set { if (_netSummary != value) { _netSummary = value; Notify("NetSummary"); Notify("LiveBannerText"); Notify("LiveDetailSummary"); } }
    }

    private string _childProcsText = "无派生子进程";
    public string ChildProcsText {
        get { return _childProcsText; }
        set { if (_childProcsText != value) { _childProcsText = value; Notify("ChildProcsText"); Notify("LiveDetailSummary"); } }
    }

    private string _touchedFilesText = "运行期间暂未触发工作区文件修改";
    public string TouchedFilesText {
        get { return _touchedFilesText; }
        set { if (_touchedFilesText != value) { _touchedFilesText = value; Notify("TouchedFilesText"); Notify("LiveDetailSummary"); } }
    }

    public string LiveBannerText {
        get {
            string net = string.IsNullOrEmpty(NetSummary) ? "无端口监听" : NetSummary;
            return string.Format("{0}  |  耗时/结果: {1}  |  资源: {2}  |  风险: {3}  |  网络: {4}", StateText, ResultText, ResourceUsage, RiskBadge, net);
        }
    }

    public string FormatFullDetail() {
        StringBuilder sb = new StringBuilder();
        sb.AppendLine("【所属 Agent】 " + AgentInstance + "   |   【进程标识】 " + ProcessDisplay + "   |   【启动时间】 " + TimeStr);
        sb.AppendLine("【当前状态】   " + StateText + "   |   【耗时与退出码】 " + ResultText + "   |   【内存/CPU】 " + ResourceUsage);
        sb.AppendLine("【风险判定】   " + RiskBadge + " — " + RiskReason);
        sb.AppendLine("【调用族谱】   " + AncestryChain);
        sb.AppendLine("【工作目录】   " + CwdFull);
        sb.AppendLine("【网络与端口】 " + (string.IsNullOrEmpty(NetSummary) ? "无端口监听或外联" : NetSummary));
        sb.AppendLine("【派生子进程】 " + ChildProcsText);
        sb.AppendLine("【关联文件流】 " + TouchedFilesText);
        sb.AppendLine();
        sb.AppendLine("==================== 完整命令行 (CommandLine) ====================");
        sb.AppendLine(FullCommand);
        if (!string.IsNullOrEmpty(DecodedText)) {
            sb.AppendLine();
            sb.AppendLine("==================== 自动解码与剥壳明文 ====================");
            sb.AppendLine(DecodedText);
        }
        return sb.ToString();
    }

    public string LiveDetailSummary {
        get { return FormatFullDetail(); }
    }
}

public static class SentinelNativeApiV8 {
    public const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
    public const uint PROCESS_QUERY_INFORMATION = 0x0400;
    public const uint PROCESS_VM_READ = 0x0010;
    public const uint PROCESS_SUSPEND_RESUME = 0x0800;
    public const uint STILL_ACTIVE = 259;

    private const int AF_INET = 2;
    private const int AF_INET6 = 23;
    private const int TCP_TABLE_OWNER_PID_ALL = 5;

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GetExitCodeProcess(IntPtr hProcess, out uint lpExitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool IsWow64Process(IntPtr hProcess, out bool wow64Process);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadProcessMemory(
        IntPtr hProcess,
        IntPtr lpBaseAddress,
        [Out] byte[] lpBuffer,
        int dwSize,
        out IntPtr lpNumberOfBytesRead);

    [DllImport("ntdll.dll", SetLastError = true)]
    public static extern int NtSuspendProcess(IntPtr processHandle);

    [DllImport("ntdll.dll", SetLastError = true)]
    public static extern int NtResumeProcess(IntPtr processHandle);

    [DllImport("ntdll.dll", SetLastError = true)]
    private static extern int NtQueryInformationProcess(
        IntPtr processHandle,
        int processInformationClass,
        ref PROCESS_BASIC_INFORMATION processInformation,
        int processInformationLength,
        out int returnLength);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(
        IntPtr pTcpTable,
        ref int dwOutBufLen,
        bool sort,
        int ipVersion,
        int tblClass,
        uint reserved);

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_BASIC_INFORMATION {
        public IntPtr Reserved1;
        public IntPtr PebBaseAddress;
        public IntPtr Reserved2_0;
        public IntPtr Reserved2_1;
        public IntPtr UniqueProcessId;
        public IntPtr InheritedFromUniqueProcessId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_TCPROW_OWNER_PID {
        public uint state;
        public uint localAddr;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public byte[] localPort;
        public uint remoteAddr;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public byte[] remotePort;
        public uint owningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_TCP6ROW_OWNER_PID {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] localAddr;
        public uint localScopeId;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public byte[] localPort;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] remoteAddr;
        public uint remoteScopeId;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public byte[] remotePort;
        public uint state;
        public uint owningPid;
    }

    public static int? TryGetExitCode(IntPtr hProcess) {
        if (hProcess == IntPtr.Zero) return null;
        uint code;
        if (GetExitCodeProcess(hProcess, out code)) {
            if (code == STILL_ACTIVE) return null;
            return unchecked((int)code);
        }
        return null;
    }

    public static bool SuspendPid(uint pid) {
        IntPtr h = OpenProcess(PROCESS_SUSPEND_RESUME, false, pid);
        if (h == IntPtr.Zero) return false;
        try { return NtSuspendProcess(h) == 0; }
        finally { CloseHandle(h); }
    }

    public static bool ResumePid(uint pid) {
        IntPtr h = OpenProcess(PROCESS_SUSPEND_RESUME, false, pid);
        if (h == IntPtr.Zero) return false;
        try { return NtResumeProcess(h) == 0; }
        finally { CloseHandle(h); }
    }

    public static string TryGetProcessCwd(uint pid) {
        if (IntPtr.Size != 8) return "";
        IntPtr hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid);
        if (hProc == IntPtr.Zero) return "";
        try {
            bool isWow64 = false;
            if (IsWow64Process(hProc, out isWow64) && isWow64) return "";

            PROCESS_BASIC_INFORMATION pbi = new PROCESS_BASIC_INFORMATION();
            int retLen;
            int status = NtQueryInformationProcess(hProc, 0, ref pbi, Marshal.SizeOf(pbi), out retLen);
            if (status != 0 || pbi.PebBaseAddress == IntPtr.Zero) return "";

            byte[] ptrBuf = new byte[8];
            IntPtr bytesRead;
            if (!ReadProcessMemory(hProc, (IntPtr)((long)pbi.PebBaseAddress + 0x20), ptrBuf, 8, out bytesRead)) return "";
            long procParamsPtr = BitConverter.ToInt64(ptrBuf, 0);
            if (procParamsPtr == 0) return "";

            byte[] usBuf = new byte[16];
            if (!ReadProcessMemory(hProc, (IntPtr)(procParamsPtr + 0x38), usBuf, 16, out bytesRead)) return "";
            ushort strLen = BitConverter.ToUInt16(usBuf, 0);
            long strPtr = BitConverter.ToInt64(usBuf, 8);
            if (strLen == 0 || strLen > 1024 || strPtr == 0) return "";

            byte[] pathBytes = new byte[strLen];
            if (!ReadProcessMemory(hProc, (IntPtr)strPtr, pathBytes, strLen, out bytesRead)) return "";
            string cwd = Encoding.Unicode.GetString(pathBytes).TrimEnd('\\', '\0');
            if (Regex.IsMatch(cwd, @"^([a-zA-Z]:\\|\\\\)")) return cwd;
            return "";
        } catch { return ""; }
        finally { CloseHandle(hProc); }
    }

    public static string GetFastTcpSummary(uint targetPid) {
        List<string> results = new List<string>();
        QueryTcp4(targetPid, results);
        QueryTcp6(targetPid, results);
        return string.Join(", ", results);
    }

    private static void QueryTcp4(uint targetPid, List<string> results) {
        int bufferSize = 0;
        GetExtendedTcpTable(IntPtr.Zero, ref bufferSize, false, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
        if (bufferSize <= 0) return;
        IntPtr tcpTablePtr = Marshal.AllocHGlobal(bufferSize);
        try {
            if (GetExtendedTcpTable(tcpTablePtr, ref bufferSize, false, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != 0) return;
            int rowCount = Marshal.ReadInt32(tcpTablePtr);
            IntPtr rowPtr = (IntPtr)((long)tcpTablePtr + 4);
            int rowSize = Marshal.SizeOf(typeof(MIB_TCPROW_OWNER_PID));
            for (int i = 0; i < rowCount; i++) {
                MIB_TCPROW_OWNER_PID row = (MIB_TCPROW_OWNER_PID)Marshal.PtrToStructure(rowPtr, typeof(MIB_TCPROW_OWNER_PID));
                if (row.owningPid == targetPid) {
                    int lPort = (row.localPort[0] << 8) + row.localPort[1];
                    if (row.state == 2) {
                        string item = "监听:" + lPort;
                        if (!results.Contains(item)) results.Add(item);
                    } else if (row.state == 5) {
                        string ipStr = (new IPAddress(row.remoteAddr)).ToString();
                        if (ipStr != "127.0.0.1" && ipStr != "0.0.0.0") {
                            int rPort = (row.remotePort[0] << 8) + row.remotePort[1];
                            string item = "外联:" + ipStr + ":" + rPort;
                            if (!results.Contains(item)) results.Add(item);
                        }
                    }
                }
                rowPtr = (IntPtr)((long)rowPtr + rowSize);
            }
        } catch {} finally { Marshal.FreeHGlobal(tcpTablePtr); }
    }

    private static void QueryTcp6(uint targetPid, List<string> results) {
        int bufferSize = 0;
        GetExtendedTcpTable(IntPtr.Zero, ref bufferSize, false, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0);
        if (bufferSize <= 0) return;
        IntPtr tcpTablePtr = Marshal.AllocHGlobal(bufferSize);
        try {
            if (GetExtendedTcpTable(tcpTablePtr, ref bufferSize, false, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0) != 0) return;
            int rowCount = Marshal.ReadInt32(tcpTablePtr);
            IntPtr rowPtr = (IntPtr)((long)tcpTablePtr + 4);
            int rowSize = Marshal.SizeOf(typeof(MIB_TCP6ROW_OWNER_PID));
            for (int i = 0; i < rowCount; i++) {
                MIB_TCP6ROW_OWNER_PID row = (MIB_TCP6ROW_OWNER_PID)Marshal.PtrToStructure(rowPtr, typeof(MIB_TCP6ROW_OWNER_PID));
                if (row.owningPid == targetPid) {
                    int lPort = (row.localPort[0] << 8) + row.localPort[1];
                    if (row.state == 2) {
                        string item = "监听:" + lPort;
                        if (!results.Contains(item)) results.Add(item);
                    } else if (row.state == 5) {
                        string ipStr = (new IPAddress(row.remoteAddr)).ToString();
                        if (ipStr != "::1" && ipStr != "::") {
                            int rPort = (row.remotePort[0] << 8) + row.remotePort[1];
                            string item = "外联:[" + ipStr + "]:" + rPort;
                            if (!results.Contains(item)) results.Add(item);
                        }
                    }
                }
                rowPtr = (IntPtr)((long)rowPtr + rowSize);
            }
        } catch {} finally { Marshal.FreeHGlobal(tcpTablePtr); }
    }
}
"@
    Add-Type -TypeDefinition $NativeCode -ErrorAction SilentlyContinue
}

# ============================================================================
# 2. 全栈工具链字典、多 Agent 实例识别、CWD 智能解析与双轨快照
# ============================================================================
$Script:WatchedProcessNames = @{
    "powershell" = $true; "pwsh"    = $true; "cmd"      = $true; "wsl"      = $true; "bash"     = $true; "sh" = $true
    "git"        = $true; "gh"      = $true; "rg"       = $true; "curl"     = $true; "wget"     = $true
    "ssh"        = $true; "scp"     = $true; "tar"      = $true; "7z"       = $true
    "node"       = $true; "npm"     = $true; "npx"      = $true; "pnpm"     = $true; "yarn"     = $true; "bun" = $true; "deno" = $true
    "python"     = $true; "python3" = $true; "pip"      = $true; "pip3"     = $true; "uv"       = $true; "poetry" = $true; "conda" = $true
    "go"         = $true; "cargo"   = $true; "rustc"    = $true; "dotnet"   = $true; "msbuild"  = $true
    "java"       = $true; "javac"   = $true; "mvn"      = $true; "gradle"   = $true; "cmake"    = $true
    "make"       = $true; "ninja"   = $true; "gcc"      = $true; "g++"      = $true; "clang"    = $true
    "php"        = $true; "composer"= $true; "ruby"     = $true
    "docker"     = $true; "kubectl" = $true; "helm"     = $true; "terraform"= $true
    "az"         = $true; "aws"     = $true; "gcloud"   = $true
}

if (-not [string]::IsNullOrWhiteSpace($ExtraWatchNames)) {
    foreach ($customName in ($ExtraWatchNames -split '[,;\s]+')) {
        $clean = ($customName -replace '\.exe$', '').Trim().ToLower()
        if ($clean) { $Script:WatchedProcessNames[$clean] = $true }
    }
}

$Script:BackupRoot = Join-Path $env:TEMP "AgentSentinel_ShadowBackups"
if (-not (Test-Path $Script:BackupRoot)) {
    New-Item -ItemType Directory -Path $Script:BackupRoot -Force | Out-Null
}

function script:Resolve-ProcessCwdSmart {
    param([uint32]$TargetPid, [string]$CmdLine, [string]$DefaultWorkspace)
    $pebCwd = [SentinelNativeApiV8]::TryGetProcessCwd($TargetPid)
    if ($pebCwd) { return $pebCwd }

    if ($CmdLine) {
        if ($CmdLine -match '(?i)(?:cd\s+(?:/d\s+)?|Set-Location\s+(?:-Path\s+)?|-WorkingDirectory\s+)["'']?([a-zA-Z]:\\[^"'';&|]+)') {
            return $Matches[1].Trim()
        }
        if ($CmdLine -match '(?i)-C\s+["'']?([a-zA-Z]:\\[^"''\s]+)') {
            return $Matches[1].Trim()
        }
    }
    return ""
}

function script:Get-ProcessResourceSummary {
    param([System.Diagnostics.Process]$LiveProc)
    if ($null -eq $LiveProc) { return "-" }
    try {
        $memMb = [Math]::Round($LiveProc.WorkingSet64 / 1MB, 1)
        $cpuSec = [Math]::Round($LiveProc.TotalProcessorTime.TotalSeconds, 1)
        $warn = if ($memMb -gt 1024) { "⚠️" } else { "" }
        return "${warn}${memMb}MB | CPU:${cpuSec}s"
    } catch {
        return "-"
    }
}

function script:Query-CimProcessesByPids {
    param([System.Collections.Generic.List[uint32]]$PidList)
    $resultMap = @{}
    if ($null -eq $PidList -or $PidList.Count -eq 0) { return $resultMap }

    $batchSize = 15
    for ($i = 0; $i -lt $PidList.Count; $i += $batchSize) {
        $end = [Math]::Min($i + $batchSize - 1, $PidList.Count - 1)
        $slice = $PidList[$i..$end]
        $filterStr = ($slice | ForEach-Object { "ProcessId = $_" }) -join " OR "
        $rows = Get-CimInstance Win32_Process -Filter $filterStr -Property ProcessId, Name, ParentProcessId, CommandLine
        foreach ($r in $rows) {
            if ($null -ne $r) {
                $resultMap[[uint32]$r.ProcessId] = $r
            }
        }
    }
    return $resultMap
}

function script:Get-RelativeWorkspacePath {
    param([string]$BasePath, [string]$FullPath)
    if ([string]::IsNullOrWhiteSpace($BasePath) -or [string]::IsNullOrWhiteSpace($FullPath)) { return $FullPath }
    $normBase = [System.IO.Path]::GetFullPath($BasePath).TrimEnd('\', '/') + "\"
    $normFull = [System.IO.Path]::GetFullPath($FullPath)
    if ($normFull.StartsWith($normBase, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $normFull.Substring($normBase.Length)
    }
    return $normFull
}

function script:Read-Utf8LinesSafe {
    param([string]$FilePath)
    if (-not $FilePath -or -not (Test-Path $FilePath -PathType Leaf)) { return @() }
    try {
        return [System.IO.File]::ReadAllLines($FilePath, [System.Text.Encoding]::UTF8)
    } catch {
        return @(Get-Content -Path $FilePath -ErrorAction SilentlyContinue)
    }
}

function script:Get-FileDiffPreview {
    param([string]$SnapshotFile, [string]$CurrentFile)
    if (-not $SnapshotFile -or -not (Test-Path $SnapshotFile)) {
        if (Test-Path $CurrentFile) {
            $lines = Read-Utf8LinesSafe -FilePath $CurrentFile
            $previewLines = if ($lines.Count -gt 35) { $lines[0..34] } else { $lines }
            return ("[会话期间新建文件 - 当前前 35 行内容预览]:`r`n" + ($previewLines -join "`r`n"))
        }
        return "(新建文件已被删除)"
    }
    if (-not (Test-Path $CurrentFile)) {
        return "⚠️ 当前文件已被 Agent 删除！点击【⏪ 回退上一版】或【⏮️ 还原基线】可立即恢复该文件。"
    }

    $oldLines = @(Read-Utf8LinesSafe -FilePath $SnapshotFile)
    $newLines = @(Read-Utf8LinesSafe -FilePath $CurrentFile)
    $diffs = Compare-Object -ReferenceObject $oldLines -DifferenceObject $newLines -PassThru:$false
    if (-not $diffs -or $diffs.Count -eq 0) {
        return "✅ 当前文件内容与对比快照完全一致（无实质文本行差异）。"
    }

    $out = New-Object System.Collections.Generic.List[string]
    $out.Add("📊 行数变化: 快照 $($oldLines.Count) 行 ➔ 当前 $($newLines.Count) 行 (差异行: $($diffs.Count) 处，最多展示前 40 处):")
    $count = 0
    foreach ($d in $diffs) {
        if ($count -ge 40) {
            $out.Add("... (其余差异行已省略)")
            break
        }
        if ($d.SideIndicator -eq "<=") {
            $out.Add("- [快照原内容] $($d.InputObject)")
        } else {
            $out.Add("+ [当前新内容] $($d.InputObject)")
        }
        $count++
    }
    return ($out -join "`r`n")
}

function script:Decode-AgentCommand {
    param([string]$CmdLine)
    if ([string]::IsNullOrWhiteSpace($CmdLine)) { return "" }
    $results = @()

    if ($CmdLine -match '(?i)\s-(?:e|ec|enc|encodedcommand)\s+([A-Za-z0-9+/=]{8,})') {
        try {
            $bytes = [System.Convert]::FromBase64String($Matches[1])
            $decoded = [System.Text.Encoding]::Unicode.GetString($bytes).Trim()
            if ($decoded) { $results += "[EncodedCommand 解码]:`n$decoded" }
        } catch {}
    }

    $b64Matches = [regex]::Matches($CmdLine, "FromBase64String\(['`"]([A-Za-z0-9+/=]{12,})['`"]\)")
    foreach ($m in $b64Matches) {
        try {
            $raw = [System.Convert]::FromBase64String($m.Groups[1].Value)
            $utf8 = [System.Text.Encoding]::UTF8.GetString($raw).Trim()
            if ($utf8) { $results += "[内联 Base64 解码]:`n$utf8" }
        } catch {}
    }

    if ($CmdLine -match '(?i)cmd(?:\.exe)?\s+(?:/[a-z]\s+)*?/c\s+(.+)$') {
        $results += "[CMD 剥壳载荷]: $($Matches[1].Trim('"'))"
    }

    return ($results -join "`n----------------------------------------`n")
}

function script:Evaluate-CommandRisk {
    param([string]$CmdLine, [string]$DecodedText)
    $fullText = "$CmdLine`n$DecodedText"

    $highRiskRules = @(
        @{ Pattern = '(?i)\b(Get-Clipboard|Windows\.Forms\.Clipboard)'; Reason = "尝试后台静默读取系统剪贴板" },
        @{ Pattern = '(?i)(\.env\b|id_rsa|id_ed25519|authorized_keys|\.aws[\\/]credentials|\.npmrc|\.pypirc)'; Reason = "触碰高敏感密钥或凭据文件" },
        @{ Pattern = '(?i)\b(rm\s+-[rRfF]{2,}|Remove-Item\b.*-(Recurse|Force)|del\s+/[fFsSqQ]|rmdir\s+/s)'; Reason = "递归或强制删除文件/目录" },
        @{ Pattern = '(?i)\bgit\s+(reset\s+--hard|clean\s+-[fd]|push\s+.*(-f|--force)|checkout\s+--\s+\.)'; Reason = "不可逆的 Git 历史重置或丢弃工作区修改" },
        @{ Pattern = '(?i)\b(Format-Volume|Clear-Disk|reg\s+delete|Stop-Process\b.*-Force|taskkill\s+/f)'; Reason = "系统级破坏或强制杀死进程" },
        @{ Pattern = '(?i)\b(Invoke-Expression|iex\b|DownloadString|curl\b.*\|\s*(sh|bash|pwsh|powershell))'; Reason = "动态执行内存脚本或远程管道代码" }
    )
    foreach ($rule in $highRiskRules) {
        if ($fullText -match $rule.Pattern) {
            return @{ Level = "高危"; Badge = "🔴 高危"; Score = 3; Reason = "$($rule.Reason) ($($Matches[0]))" }
        }
    }

    $mediumRiskRules = @(
        @{ Pattern = '(?i)\b(Get-ChildItem\s+env:|gci\s+env:|set\b|printenv)'; Reason = "枚举当前系统环境变量" },
        @{ Pattern = '(?i)\b(npm\s+i|npm\s+install|pip\s+install|pnpm\s+add|yarn\s+add|cargo\s+add|go\s+get|dotnet\s+add)'; Reason = "安装外部第三方依赖包" },
        @{ Pattern = '(?i)\bgit\s+(commit|push|merge|rebase|stash|branch\s+-[dD])'; Reason = "变更 Git 仓库提交状态" },
        @{ Pattern = '(?i)\b(Set-Content|Out-File|Add-Content|New-Item|Move-Item|Copy-Item)'; Reason = "通过命令行写入或移动文件" },
        @{ Pattern = '(?i)\b(Invoke-WebRequest|Invoke-RestMethod|curl\b|wget\b|ssh\b|scp\b|docker\s+run|gh\s+pr|kubectl\s+apply)'; Reason = "发起外部网络请求或部署操作" }
    )
    foreach ($rule in $mediumRiskRules) {
        if ($fullText -match $rule.Pattern) {
            return @{ Level = "修改"; Badge = "🟡 修改"; Score = 2; Reason = "$($rule.Reason) ($($Matches[0]))" }
        }
    }

    return @{ Level = "只读"; Badge = "🟢 只读"; Score = 1; Reason = "常规只读查询或编译检查" }
}

$Global:ParentRelationCache = @{}
function script:Get-ProcessAncestryAndAgent {
    param([uint32]$StartParentPid)
    $chain = New-Object System.Collections.Generic.List[string]
    $currPid = $StartParentPid
    $depth = 0
    $detectedAgent = $null
    $topMostNonShell = $null

    while ($currPid -gt 4 -and $depth -lt 6) {
        $liveName = $null
        try {
            $liveProc = [System.Diagnostics.Process]::GetProcessById([int]$currPid)
            $liveName = "$($liveProc.ProcessName).exe"
        } catch {}

        $parentPid = 0
        if ($Global:ParentRelationCache.ContainsKey($currPid) -and
            (-not $liveName -or $Global:ParentRelationCache[$currPid].Name -eq $liveName)) {
            $cached = $Global:ParentRelationCache[$currPid]
            $liveName = $cached.Name
            $parentPid = $cached.ParentPid
        } else {
            $cim = Get-CimInstance Win32_Process -Filter "ProcessId = $currPid" -Property Name, ParentProcessId
            if ($cim) {
                $liveName = $cim.Name
                $parentPid = [uint32]$cim.ParentProcessId
                $Global:ParentRelationCache[$currPid] = @{ Name = $liveName; ParentPid = $parentPid }
            } elseif (-not $liveName) {
                $liveName = "已退出($currPid)"
            }
        }

        $shortBase = ($liveName -replace '\.exe$', '')
        $displayNode = "$liveName($currPid)"

        if ($liveName -match '^(?i)(cursor|claude|windsurf|trae|code|aider|idea64|pycharm64|webstorm64|ollama|openinterpreter)\.exe$') {
            $displayNode = "🤖$displayNode"
            $detectedAgent = "🤖 $shortBase #$currPid"
        } elseif ($liveName -notmatch '^(?i)(explorer|services|wininit|svchost|conhost|WindowsTerminal)\.exe$') {
            $topMostNonShell = "⚙️ $shortBase #$currPid"
        }

        $chain.Add($displayNode)
        if ($liveName -match '^(?i)(explorer\.exe|services\.exe|wininit\.exe|svchost\.exe)$') { break }
        if ($parentPid -le 4 -or $parentPid -eq $currPid) { break }
        $currPid = $parentPid
        $depth++
    }

    $chainStr = if ($chain.Count -eq 0) { "未知宿主" } else {
        $arr = $chain.ToArray()
        [array]::Reverse($arr)
        ($arr -join " ➔ ")
    }
    $agentId = if ($detectedAgent) { $detectedAgent } elseif ($topMostNonShell) { $topMostNonShell } else { "⚙️ 独立终端" }

    return @{
        ChainString   = $chainStr
        AgentInstance = $agentId
    }
}

function script:Suspend-ProcessTree {
    param([uint32]$RootPid)
    if ($RootPid -le 4) { return $false }
    $ok = [SentinelNativeApiV8]::SuspendPid($RootPid)
    try {
        $children = Get-CimInstance Win32_Process -Filter "ParentProcessId = $RootPid" -Property ProcessId
        foreach ($c in $children) {
            if ($c.ProcessId -ne $PID) {
                Suspend-ProcessTree -RootPid ([uint32]$c.ProcessId) | Out-Null
            }
        }
    } catch {}
    return $ok
}

function script:Resume-ProcessTree {
    param([uint32]$RootPid)
    if ($RootPid -le 4) { return $false }
    $ok = [SentinelNativeApiV8]::ResumePid($RootPid)
    try {
        $children = Get-CimInstance Win32_Process -Filter "ParentProcessId = $RootPid" -Property ProcessId
        foreach ($c in $children) {
            if ($c.ProcessId -ne $PID) {
                Resume-ProcessTree -RootPid ([uint32]$c.ProcessId) | Out-Null
            }
        }
    } catch {}
    return $ok
}

function script:Stop-ProcessTree {
    param([uint32]$TargetPid)
    if ($TargetPid -le 4) { return $false }
    try {
        $children = Get-CimInstance Win32_Process -Filter "ParentProcessId = $TargetPid" -Property ProcessId
        foreach ($child in $children) {
            Stop-ProcessTree -TargetPid ([uint32]$child.ProcessId) | Out-Null
        }
        [void][SentinelNativeApiV8]::ResumePid($TargetPid)
        Stop-Process -Id $TargetPid -Force -ErrorAction SilentlyContinue
        return $true
    } catch { return $false }
}

function script:Initialize-WorkspaceSnapshot {
    param([string]$RootPath)
    if (-not (Test-Path $RootPath)) { return 0 }
    $count = 0
    $files = Get-ChildItem -Path $RootPath -File -Recurse -ErrorAction SilentlyContinue |
        Where-Object {
            $_.FullName -notmatch '([\\/]\.git[\\/]|[\\/]node_modules[\\/]|[\\/]__pycache__[\\/]|[\\/]dist[\\/]|[\\/]build[\\/]|[\\/]\.next[\\/]|[\\/]target[\\/]|[\\/]bin[\\/]|[\\/]obj[\\/]|[\\/]venv[\\/]|[\\/]\.venv[\\/])' -and
            $_.Length -lt 2MB
        } | Select-Object -First 2000

    foreach ($f in $files) {
        $rel = Get-RelativeWorkspacePath -BasePath $RootPath -FullPath $f.FullName
        $baseDest = Join-Path $Script:BackupRoot ("Baseline\" + $rel)
        $workDest = Join-Path $Script:BackupRoot ("WorkingCopy\" + $rel)
        foreach ($d in @($baseDest, $workDest)) {
            $dir = Split-Path $d -Parent
            if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
            Copy-Item -Path $f.FullName -Destination $d -Force -ErrorAction SilentlyContinue
        }
        $count++
    }
    return $count
}

function script:Find-OrphanProcesses {
    $liveProcs = [System.Diagnostics.Process]::GetProcesses()
    $livePidSet = @{}
    $candidates = New-Object System.Collections.Generic.List[uint32]

    foreach ($p in $liveProcs) {
        $livePidSet[[uint32]$p.Id] = $true
        if ($p.Id -ne $PID -and $Script:WatchedProcessNames.ContainsKey($p.ProcessName.ToLower())) {
            $candidates.Add([uint32]$p.Id)
        }
    }

    $orphans = New-Object System.Collections.Generic.List[PSObject]
    if ($candidates.Count -eq 0) { return $orphans }

    $cimMap = Query-CimProcessesByPids -PidList $candidates
    foreach ($cp in $cimMap.Values) {
        $ppid = [uint32]$cp.ParentProcessId
        if ($ppid -gt 4 -and (-not $livePidSet.ContainsKey($ppid))) {
            $net = [SentinelNativeApiV8]::GetFastTcpSummary([uint32]$cp.ProcessId)
            $orphans.Add([PSCustomObject]@{
                Pid         = [uint32]$cp.ProcessId
                Name        = $cp.Name
                DeadParent  = $ppid
                NetPorts    = if ($net) { $net } else { "无端口监听" }
                CommandLine = if ($cp.CommandLine) { $cp.CommandLine } else { "(无参数)" }
            })
        }
    }
    return $orphans
}

function script:Start-WorkspaceFileWatcher {
    param([string]$RootPath)

    $SyncContext = [PSCustomObject]@{
        Queue          = [System.Collections.Concurrent.ConcurrentQueue[PSObject]]::new()
        DebounceMap    = [System.Collections.Concurrent.ConcurrentDictionary[string, DateTime]]::new()
        SuppressUntil  = [DateTime]::MinValue
        Watcher        = $null
        Subscriptions  = @()
    }

    if (-not (Test-Path $RootPath)) { return $SyncContext }

    $fsw = New-Object System.IO.FileSystemWatcher
    $fsw.Path = $RootPath
    $fsw.IncludeSubdirectories = $true
    $fsw.NotifyFilter = [System.IO.NotifyFilters]'FileName, LastWrite, Size'

    $fswAction = {
        $ctx = $Event.MessageData
        if ($null -eq $ctx) { return }
        $now = [DateTime]::UtcNow
        if ($now -lt $ctx.SuppressUntil) { return }

        $e = $Event.SourceEventArgs
        $full = $e.FullPath
        if ([string]::IsNullOrWhiteSpace($full)) { return }

        if ($full -match '([\\/]\.git[\\/]index\.lock)$') {
            $ctx.Queue.Enqueue([PSCustomObject]@{
                TimeStr    = (Get-Date).ToString("HH:mm:ss.fff")
                ChangeType = "GitLock"
                FullPath   = $full
            })
            return
        }

        if ($full -match '([\\/]\.git[\\/]|[\\/]node_modules[\\/]|[\\/]__pycache__[\\/]|[\\/]dist[\\/]|[\\/]build[\\/]|[\\/]\.next[\\/]|[\\/]target[\\/]|[\\/]bin[\\/]|[\\/]obj[\\/]|[\\/]venv[\\/]|[\\/]\.venv[\\/]|~|\.(tmp|log|swp|pyc)$)') {
            return
        }

        if ((Test-Path $full -PathType Container)) { return }

        $changeKey = "$($e.ChangeType)|$full"
        $lastTime = [DateTime]::MinValue
        if ($ctx.DebounceMap.TryGetValue($changeKey, [ref]$lastTime)) {
            if (($now - $lastTime).TotalMilliseconds -lt 300) { return }
        }
        $ctx.DebounceMap[$changeKey] = $now

        $ctx.Queue.Enqueue([PSCustomObject]@{
            TimeStr    = (Get-Date).ToString("HH:mm:ss.fff")
            ChangeType = $e.ChangeType.ToString()
            FullPath   = $full
        })
    }

    $s1 = Register-ObjectEvent -InputObject $fsw -EventName Created -MessageData $SyncContext -Action $fswAction
    $s2 = Register-ObjectEvent -InputObject $fsw -EventName Changed -MessageData $SyncContext -Action $fswAction
    $s3 = Register-ObjectEvent -InputObject $fsw -EventName Deleted -MessageData $SyncContext -Action $fswAction
    $s4 = Register-ObjectEvent -InputObject $fsw -EventName Renamed -MessageData $SyncContext -Action $fswAction

    $fsw.EnableRaisingEvents = $true
    $SyncContext.Watcher = $fsw
    $SyncContext.Subscriptions = @($s1, $s2, $s3, $s4)
    return $SyncContext
}

function script:Stop-WorkspaceFileWatcher {
    param($SyncContext)
    if ($null -eq $SyncContext) { return }
    if ($SyncContext.Watcher) {
        $SyncContext.Watcher.EnableRaisingEvents = $false
        $SyncContext.Watcher.Dispose()
    }
    foreach ($sub in $SyncContext.Subscriptions) {
        if ($sub) { Unregister-Event -SourceIdentifier $sub.Name -ErrorAction SilentlyContinue }
    }
}

# ============================================================================
# 3. 专属“单命令独立监控与操控窗口”管理器 (支持防重复弹窗唤醒、因果文件关联、取证单导出)
# ============================================================================
$Script:PopOutCascadeIndex = 0
$Script:OpenInspectorWindows = @{}

function script:Open-CommandInspectorWindow {
    param([AgentProcessRecordV8]$ProcessRecord, [string]$UniqueWindowKey, [string]$TitleText, [string]$StaticContent)

    $lookupKey = if ($null -ne $ProcessRecord) { $ProcessRecord.UniqueKey } else { $UniqueWindowKey }
    if ($lookupKey -and $Script:OpenInspectorWindows.ContainsKey($lookupKey)) {
        $existingWin = $Script:OpenInspectorWindows[$lookupKey]
        if ($null -ne $existingWin) {
            try {
                if ($existingWin.WindowState -eq [System.Windows.WindowState]::Minimized) {
                    $existingWin.WindowState = [System.Windows.WindowState]::Normal
                }
                $existingWin.Activate() | Out-Null
                return
            } catch {
                $Script:OpenInspectorWindows.Remove($lookupKey)
            }
        }
    }

    [xml]$popXaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="🗗 单命令独立监控窗"
        Width="700" Height="510" MinWidth="480" MinHeight="300"
        WindowStartupLocation="Manual"
        Background="#0B0F19" Foreground="#F3F4F6"
        Topmost="True" FontFamily="Microsoft YaHei UI, Consolas, Segoe UI">
    <Window.Resources>
        <Style TargetType="Button">
            <Setter Property="Background" Value="#1E293B"/>
            <Setter Property="Foreground" Value="#E2E8F0"/>
            <Setter Property="BorderBrush" Value="#334155"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="Padding" Value="8,4"/>
            <Setter Property="Margin" Value="2,2"/>
            <Setter Property="Cursor" Value="Hand"/>
        </Style>
    </Window.Resources>
    <Grid Margin="10">
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
        </Grid.RowDefinitions>

        <!-- 顶部实时状态卡片 -->
        <Border Grid.Row="0" Background="#1E293B" CornerRadius="6" Padding="10,7" Margin="0,0,0,6" BorderBrush="#334155" BorderThickness="1">
            <DockPanel LastChildFill="True">
                <CheckBox x:Name="ChkPopTop" DockPanel.Dock="Right" Content="📌 窗口置顶" IsChecked="True" Foreground="#CBD5E1" VerticalAlignment="Center" Margin="8,0,0,0"/>
                <StackPanel Orientation="Vertical">
                    <TextBlock x:Name="TxtPopHeader" Text="单命令独立透视" FontWeight="Bold" FontSize="13.5" Foreground="#38BDF8"/>
                    <TextBlock x:Name="TxtPopLiveBanner" Text="实时状态同步中..." FontSize="12" Foreground="#A7F3D0" Margin="0,3,0,0"/>
                </StackPanel>
            </DockPanel>
        </Border>

        <!-- 针对该命令的独立操作与搜索工具栏 -->
        <Border Grid.Row="1" Background="#151E2E" CornerRadius="6" Padding="6,4" Margin="0,0,0,6" BorderBrush="#26334D" BorderThickness="1">
            <WrapPanel Orientation="Horizontal" VerticalAlignment="Center">
                <Button x:Name="BtnPopSuspend" Content="⏸️ 冻结此命令树" Foreground="#FCD34D" FontWeight="Bold"/>
                <Button x:Name="BtnPopResume" Content="▶️ 恢复运行" Foreground="#6EE7B7" FontWeight="Bold"/>
                <Button x:Name="BtnPopKill" Content="🛑 强杀此命令树" Foreground="#FCA5A5" FontWeight="Bold"/>
                <Button x:Name="BtnPopOpenCwd" Content="📂 打开工作目录" Foreground="#93C5FD"/>
                <Button x:Name="BtnPopCopyCmd" Content="📋 复制命令"/>
                <Button x:Name="BtnPopCopyDecoded" Content="📋 复制全文" Foreground="#FDE047"/>
                <Button x:Name="BtnPopSaveMd" Content="💾 导出取证单(.md)" Foreground="#C084FC" FontWeight="Bold"/>
            </WrapPanel>
        </Border>

        <!-- 实时同步的命令详情、关联文件改动、派生子进程与解码正文 -->
        <Border Grid.Row="2" Background="#0F172A" BorderBrush="#334155" BorderThickness="1" CornerRadius="6" Padding="8">
            <TextBox x:Name="TxtPopBody" Background="Transparent" Foreground="#E2E8F0" BorderThickness="0"
                     IsReadOnly="True" TextWrapping="Wrap" VerticalScrollBarVisibility="Auto"
                     FontFamily="Consolas, Microsoft YaHei UI" FontSize="12"/>
        </Border>
    </Grid>
</Window>
"@
    $popReader = New-Object System.Xml.XmlNodeReader $popXaml
    $popWin = [Windows.Markup.XamlReader]::Load($popReader)

    $wa = [System.Windows.SystemParameters]::WorkArea
    $offset = ($Script:PopOutCascadeIndex % 8) * 32
    $Script:PopOutCascadeIndex++
    $popWin.Left = [Math]::Max(40, [Math]::Min($wa.Right - $popWin.Width - 40, ($wa.Width - $popWin.Width) / 2 + $offset))
    $popWin.Top  = [Math]::Max(40, [Math]::Min($wa.Bottom - $popWin.Height - 40, ($wa.Height - $popWin.Height) / 2 + $offset))

    $TxtPopHeader     = $popWin.FindName("TxtPopHeader")
    $TxtPopLiveBanner = $popWin.FindName("TxtPopLiveBanner")
    $TxtPopBody       = $popWin.FindName("TxtPopBody")
    $ChkPopTop        = $popWin.FindName("ChkPopTop")
    $BtnPopSuspend    = $popWin.FindName("BtnPopSuspend")
    $BtnPopResume     = $popWin.FindName("BtnPopResume")
    $BtnPopKill       = $popWin.FindName("BtnPopKill")
    $BtnPopOpenCwd    = $popWin.FindName("BtnPopOpenCwd")
    $BtnPopCopyCmd    = $popWin.FindName("BtnPopCopyCmd")
    $BtnPopCopyDecoded= $popWin.FindName("BtnPopCopyDecoded")
    $BtnPopSaveMd     = $popWin.FindName("BtnPopSaveMd")

    if ($null -ne $ProcessRecord) {
        $popWin.Title = "🗗 独立监控: $($ProcessRecord.AgentInstance) ➔ $($ProcessRecord.ProcessDisplay)"
        $TxtPopHeader.Text = "$($ProcessRecord.AgentInstance)  ➔  $($ProcessRecord.ProcessDisplay)"
        $popWin.DataContext = $ProcessRecord

        $bBanner = New-Object System.Windows.Data.Binding("LiveBannerText")
        $bBanner.Mode = [System.Windows.Data.BindingMode]::OneWay
        [void][System.Windows.Data.BindingOperations]::SetBinding($TxtPopLiveBanner, [System.Windows.Controls.TextBlock]::TextProperty, $bBanner)

        $bBody = New-Object System.Windows.Data.Binding("LiveDetailSummary")
        $bBody.Mode = [System.Windows.Data.BindingMode]::OneWay
        [void][System.Windows.Data.BindingOperations]::SetBinding($TxtPopBody, [System.Windows.Controls.TextBox]::TextProperty, $bBody)

        $BtnPopSuspend.Add_Click({
            $rec = $popWin.DataContext
            if ($null -ne $rec -and (-not $rec.IsSuspended)) {
                if (Suspend-ProcessTree -RootPid ([uint32]$rec.Pid)) {
                    $rec.IsSuspended = $true
                    $rec.StateText = "⏸️ 树已冻结"
                }
            }
        })

        $BtnPopResume.Add_Click({
            $rec = $popWin.DataContext
            if ($null -ne $rec) {
                if (Resume-ProcessTree -RootPid ([uint32]$rec.Pid)) {
                    $rec.IsSuspended = $false
                    $rec.StateText = "⚡ 运行中"
                }
            }
        })

        $BtnPopKill.Add_Click({
            $rec = $popWin.DataContext
            if ($null -ne $rec) {
                if (Stop-ProcessTree -TargetPid ([uint32]$rec.Pid)) {
                    $rec.IsSuspended = $false
                    $rec.StateText = "🛑 已强杀"
                }
            }
        })

        $BtnPopOpenCwd.Add_Click({
            $rec = $popWin.DataContext
            if ($null -ne $rec -and $rec.CwdFull -and (Test-Path $rec.CwdFull -PathType Container)) {
                Start-Process "explorer.exe" -ArgumentList "`"$($rec.CwdFull)`""
            } else {
                [System.Windows.MessageBox]::Show("该命令的工作目录不存在或进程已退出未能捕获目录。", "提示", "OK", "Information") | Out-Null
            }
        })

        $BtnPopCopyCmd.Add_Click({
            $rec = $popWin.DataContext
            if ($null -ne $rec) { [System.Windows.Clipboard]::SetText($rec.FullCommand) }
        })

        $BtnPopCopyDecoded.Add_Click({
            [System.Windows.Clipboard]::SetText($TxtPopBody.Text)
        })

        $BtnPopSaveMd.Add_Click({
            $rec = $popWin.DataContext
            $mdFile = Join-Path ([Environment]::GetFolderPath("Desktop")) ("Agent_Command_Forensics_PID" + $rec.Pid + "_" + (Get-Date -Format "HHmmss") + ".md")
            $mdContent = @(
                "# 🛡️ AI Agent 单命令执行取证报告",
                "",
                "- **所属 Agent 实例**: $($rec.AgentInstance)",
                "- **目标进程**: $($rec.ProcessDisplay)",
                "- **捕获时间**: $($rec.TimeStr)",
                "- **执行状态与退出码**: $($rec.StateText) ($($rec.ResultText))",
                "- **内存与 CPU 占用**: $($rec.ResourceUsage)",
                "- **风险评级**: $($rec.RiskBadge) — $($rec.RiskReason)",
                "- **调用族谱链**: ``$($rec.AncestryChain)``",
                "- **工作目录 (CWD)**: ``$($rec.CwdFull)``",
                "- **双栈网络端口**: $($rec.NetSummary)",
                "- **派生子进程**: $($rec.ChildProcsText)",
                "- **运行期间关联的文件改动**: $($rec.TouchedFilesText)",
                "",
                "## 1. 完整原始命令行 (CommandLine)",
                '```powershell',
                $rec.FullCommand,
                '```'
            )
            if ($rec.DecodedText) {
                $mdContent += @(
                    "",
                    "## 2. Base64 / 嵌套壳解码明文",
                    '```powershell',
                    $rec.DecodedText,
                    '```'
                )
            }
            [System.IO.File]::WriteAllLines($mdFile, $mdContent, [System.Text.Encoding]::UTF8)
            [System.Windows.MessageBox]::Show("单命令取证报告已导出至桌面：`n$mdFile", "导出成功", "OK", "Information") | Out-Null
        })
    } else {
        $popWin.Title = $TitleText
        $TxtPopHeader.Text = $TitleText
        $TxtPopLiveBanner.Text = "静态快照 / 代码对比独立视图"
        $BtnPopSuspend.Visibility = [System.Windows.Visibility]::Collapsed
        $BtnPopResume.Visibility  = [System.Windows.Visibility]::Collapsed
        $BtnPopKill.Visibility    = [System.Windows.Visibility]::Collapsed
        $BtnPopOpenCwd.Visibility = [System.Windows.Visibility]::Collapsed
        $BtnPopCopyCmd.Visibility = [System.Windows.Visibility]::Collapsed
        $TxtPopBody.Text = $StaticContent
        $BtnPopCopyDecoded.Add_Click({ [System.Windows.Clipboard]::SetText($TxtPopBody.Text) })
        $BtnPopSaveMd.Add_Click({
            $mdFile = Join-Path ([Environment]::GetFolderPath("Desktop")) ("Agent_Snapshot_Forensics_" + (Get-Date -Format "HHmmss") + ".md")
            [System.IO.File]::WriteAllText($mdFile, $TxtPopBody.Text, [System.Text.Encoding]::UTF8)
            [System.Windows.MessageBox]::Show("已导出至桌面：`n$mdFile", "导出成功", "OK", "Information") | Out-Null
        })
    }

    if ($lookupKey) {
        $Script:OpenInspectorWindows[$lookupKey] = $popWin
        $popWin.Tag = $lookupKey
        $popWin.Add_Closed({
            param($sender, $e)
            if ($sender.Tag -and $Script:OpenInspectorWindows.ContainsKey($sender.Tag)) {
                $Script:OpenInspectorWindows.Remove($sender.Tag)
            }
        })
    }

    $ChkPopTop.Add_Click({ $popWin.Topmost = [bool]$ChkPopTop.IsChecked })
    $popWin.Show()
}

# ============================================================================
# 4. 四维全景深色悬浮舱 (WPF GUI 主窗口 v8.0 - 因果关联 + 2.5秒智能瞄准防抖)
# ============================================================================
function Start-UltimateGui {
    try {
        Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Windows.Forms, System.Drawing -ErrorAction Stop
    } catch {
        Write-Host "⚠️ 当前环境无法加载 WPF 图形组件，已自动降级切换至 CLI 终端模式。" -ForegroundColor Yellow
        Start-UltimateCli
        return
    }

    [xml]$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="🛡️ 🛡️ AI Agent 全栈行为感知与安全哨兵舱 (Agent Sentinel v8.0)"
        Width="1240" Height="730" MinWidth="440" MinHeight="230"
        WindowStartupLocation="CenterScreen"
        Background="#0B0F19" Foreground="#F3F4F6"
        Topmost="True" FontFamily="Microsoft YaHei UI, Consolas, Segoe UI">
    <Window.Resources>
        <Style TargetType="Button">
            <Setter Property="Background" Value="#1E293B"/>
            <Setter Property="Foreground" Value="#E2E8F0"/>
            <Setter Property="BorderBrush" Value="#334155"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="Padding" Value="8,4"/>
            <Setter Property="Margin" Value="2,2"/>
            <Setter Property="Cursor" Value="Hand"/>
        </Style>
        <Style TargetType="DataGridColumnHeader">
            <Setter Property="Background" Value="#1E293B"/>
            <Setter Property="Foreground" Value="#94A3B8"/>
            <Setter Property="Padding" Value="8,5"/>
            <Setter Property="BorderBrush" Value="#334155"/>
            <Setter Property="BorderThickness" Value="0,0,1,1"/>
            <Setter Property="FontWeight" Value="Bold"/>
        </Style>
        <Style TargetType="DataGridRow">
            <Setter Property="Background" Value="#0F172A"/>
            <Setter Property="Foreground" Value="#E2E8F0"/>
            <Style.Triggers>
                <Trigger Property="IsSelected" Value="True">
                    <Setter Property="Background" Value="#1D4ED8"/>
                    <Setter Property="Foreground" Value="#FFFFFF"/>
                </Trigger>
            </Style.Triggers>
        </Style>
        <Style TargetType="TabItem">
            <Setter Property="Background" Value="#1E293B"/>
            <Setter Property="Foreground" Value="#94A3B8"/>
            <Setter Property="Padding" Value="10,5"/>
            <Setter Property="FontWeight" Value="Bold"/>
            <Style.Triggers>
                <Trigger Property="IsSelected" Value="True">
                    <Setter Property="Background" Value="#2563EB"/>
                    <Setter Property="Foreground" Value="#FFFFFF"/>
                </Trigger>
            </Style.Triggers>
        </Style>
    </Window.Resources>

    <Grid Margin="10">
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*" MinHeight="140"/>
            <RowDefinition Height="6"/>
            <RowDefinition x:Name="RowDetailPanel" Height="185"/>
            <RowDefinition x:Name="RowFooterPanel" Height="Auto"/>
        </Grid.RowDefinitions>

        <!-- 顶部全景状态栏 -->
        <Border Grid.Row="0" Background="#1E293B" CornerRadius="6" Padding="10,6" Margin="0,0,0,6" BorderBrush="#334155" BorderThickness="1">
            <DockPanel LastChildFill="True">
                <WrapPanel DockPanel.Dock="Right" Orientation="Horizontal" VerticalAlignment="Center">
                    <TextBlock x:Name="TxtHoverAnchorBadge" Text="🎯 智能瞄准防移位中" Foreground="#38BDF8" FontSize="11.5" VerticalAlignment="Center" Margin="0,0,10,0" Visibility="Collapsed" FontWeight="Bold"/>
                    <CheckBox x:Name="ChkCircuitBreaker" Content="⚡ 按Agent独立熔断" IsChecked="True" Foreground="#FBBF24" VerticalAlignment="Center" Margin="0,0,10,0" FontWeight="Bold"/>
                    <CheckBox x:Name="ChkAutoFreeze" Content="🔴 高危自动冻结树" IsChecked="True" Foreground="#FCA5A5" VerticalAlignment="Center" Margin="0,0,10,0" FontWeight="Bold"/>
                    <CheckBox x:Name="ChkTrayAlert" Content="🔔 气泡" IsChecked="True" Foreground="#93C5FD" VerticalAlignment="Center" Margin="0,0,8,0"/>
                    <CheckBox x:Name="ChkTopmost" Content="📌 置顶" IsChecked="True" Foreground="#CBD5E1" VerticalAlignment="Center" Margin="0,0,8,0"/>
                    <Slider x:Name="SliderOpacity" Minimum="0.45" Maximum="1.0" Value="0.96" Width="55" VerticalAlignment="Center" Margin="0,0,8,0" ToolTip="调节窗口透明度"/>
                    <Button x:Name="BtnMiniMode" Content="🗕 迷你雷达" Foreground="#38BDF8" FontWeight="Bold" Padding="6,2"/>
                </WrapPanel>

                <WrapPanel Orientation="Horizontal" VerticalAlignment="Center">
                    <Ellipse x:Name="StatusPulse" Width="11" Height="11" Fill="#10B981" Margin="0,0,7,0" VerticalAlignment="Center"/>
                    <TextBlock x:Name="TxtStatusTitle" Text="四维哨兵待命中" FontWeight="Bold" FontSize="13.5" Foreground="#10B981" VerticalAlignment="Center"/>
                    <TextBlock x:Name="TxtStats" Text="  |  并发Agent: 0  |  活跃进程: 0  |  命令: 0  |  文件: 0" FontSize="12" Foreground="#CBD5E1" VerticalAlignment="Center" Margin="6,0,0,0"/>
                </WrapPanel>
            </DockPanel>
        </Border>

        <!-- 多 Agent 通道筛选与快捷工具栏 -->
        <Border x:Name="BorderToolbar" Grid.Row="1" Background="#151E2E" CornerRadius="6" Padding="8,5" Margin="0,0,0,6" BorderBrush="#26334D" BorderThickness="1">
            <DockPanel LastChildFill="True">
                <WrapPanel DockPanel.Dock="Left" Orientation="Horizontal" VerticalAlignment="Center" Margin="0,0,8,0">
                    <TextBlock Text="🤖 Agent通道:" Foreground="#38BDF8" FontWeight="Bold" VerticalAlignment="Center" Margin="2,0,4,0"/>
                    <ComboBox x:Name="CmbAgentChannel" Width="155" SelectedIndex="0" Margin="0,0,8,0" VerticalContentAlignment="Center"/>
                    <TextBlock Text="🔍 搜索:" Foreground="#94A3B8" VerticalAlignment="Center" Margin="2,0,4,0"/>
                    <TextBox x:Name="TxtFilter" Width="135" Background="#0B0F19" Foreground="#F3F4F6" BorderBrush="#334155" Padding="5,2" VerticalContentAlignment="Center"/>
                </WrapPanel>

                <WrapPanel Orientation="Horizontal" HorizontalAlignment="Right" VerticalAlignment="Center">
                    <Button x:Name="BtnPopOut" Content="🗗 跳出独立窗口 (双击行或按Enter)" Foreground="#38BDF8" FontWeight="Bold" Background="#1E3A8A" BorderBrush="#3B82F6"/>
                    <Button x:Name="BtnFreezeAgent" Content="❄️ 冻结该Agent" Foreground="#67E8F9" FontWeight="Bold"/>
                    <Button x:Name="BtnSuspend" Content="⏸️ 冻结树" Foreground="#FCD34D"/>
                    <Button x:Name="BtnResume" Content="▶️ 恢复树" Foreground="#6EE7B7"/>
                    <Button x:Name="BtnKill" Content="🛑 强杀树" Foreground="#FCA5A5" FontWeight="Bold"/>
                    <Button x:Name="BtnRollbackPrev" Content="⏪ 回退上一版" Foreground="#E879F9" FontWeight="Bold"/>
                    <Button x:Name="BtnRollbackFile" Content="⏮️ 还原基线" Foreground="#C084FC" FontWeight="Bold"/>
                    <Button x:Name="BtnCleanOrphans" Content="🧹 清孤儿/锁" Foreground="#FDBA74"/>
                    <Button x:Name="BtnExport" Content="💾 导出"/>
                </WrapPanel>
            </DockPanel>
        </Border>

        <!-- 四维监控标签页 (双击任意行或按 Enter 键即刻跳出独立窗口，自动关联文件改动与内存占用) -->
        <TabControl x:Name="MainTabs" Grid.Row="2" Background="#0F172A" BorderBrush="#334155" BorderThickness="1">
            <TabItem Header="🚀 1. 多Agent并发命令流 (💡双击任意行或按Enter即跳出独立监控窗)">
                <DataGrid x:Name="GridProcesses" AutoGenerateColumns="False" IsReadOnly="True"
                          Background="#0B0F19" BorderThickness="0" GridLinesVisibility="Horizontal"
                          HorizontalGridLinesBrush="#1E293B" RowHeaderWidth="0" SelectionMode="Single" FontSize="12"
                          ToolTip="💡 提示：直接鼠标双击任意一行（或选中后按 Enter 键），即可跳出专属独立窗口单独查看该命令的实时状态、派生子进程与关联文件修改！">
                    <DataGrid.Columns>
                        <DataGridTextColumn Header="时间" Binding="{Binding TimeStr}" Width="75"/>
                        <DataGridTextColumn Header="所属 Agent 实例" Binding="{Binding AgentInstance}" Width="122"/>
                        <DataGridTextColumn Header="状态" Binding="{Binding StateText}" Width="90"/>
                        <DataGridTextColumn Header="风险" Binding="{Binding RiskBadge}" Width="62"/>
                        <DataGridTextColumn Header="进程 (PID)" Binding="{Binding ProcessDisplay}" Width="115"/>
                        <DataGridTextColumn Header="工作目录 (CWD)" Binding="{Binding CwdDisplay}" Width="120"/>
                        <DataGridTextColumn Header="执行命令 / 自动解码摘要 (双击跳出独立窗口)" Binding="{Binding CommandPreview}" Width="*"/>
                        <DataGridTextColumn Header="耗时 &amp; 退出码" Binding="{Binding ResultText}" Width="105"/>
                        <DataGridTextColumn Header="内存 &amp; CPU" Binding="{Binding ResourceUsage}" Width="105"/>
                        <DataGridTextColumn Header="双栈端口/外联" Binding="{Binding NetSummary}" Width="95"/>
                    </DataGrid.Columns>
                </DataGrid>
            </TabItem>

            <TabItem Header="📝 2. 文件篡改哨兵 &amp; 双轨时光机 (双击跳出独立 Diff 窗)">
                <DataGrid x:Name="GridFiles" AutoGenerateColumns="False" IsReadOnly="True"
                          Background="#0B0F19" BorderThickness="0" GridLinesVisibility="Horizontal"
                          HorizontalGridLinesBrush="#1E293B" RowHeaderWidth="0" SelectionMode="Single" FontSize="12">
                    <DataGrid.Columns>
                        <DataGridTextColumn Header="时间" Binding="{Binding TimeStr}" Width="85"/>
                        <DataGridTextColumn Header="动作类型" Binding="{Binding ActionBadge}" Width="90"/>
                        <DataGridTextColumn Header="归因触发进程" Binding="{Binding TriggerProcess}" Width="170"/>
                        <DataGridTextColumn Header="相对路径" Binding="{Binding RelativePath}" Width="260"/>
                        <DataGridTextColumn Header="双轨微快照状态 (基线 / 上一版本)" Binding="{Binding BackupStatus}" Width="220"/>
                        <DataGridTextColumn Header="完整文件路径 (双击跳出独立 Diff 窗)" Binding="{Binding FullPath}" Width="*"/>
                    </DataGrid.Columns>
                </DataGrid>
            </TabItem>

            <TabItem Header="🧠 3. 常驻 Shell 内部指令嗅探 (双击跳出独立脚本窗)">
                <DataGrid x:Name="GridScriptBlocks" AutoGenerateColumns="False" IsReadOnly="True"
                          Background="#0B0F19" BorderThickness="0" GridLinesVisibility="Horizontal"
                          HorizontalGridLinesBrush="#1E293B" RowHeaderWidth="0" SelectionMode="Single" FontSize="12">
                    <DataGrid.Columns>
                        <DataGridTextColumn Header="时间" Binding="{Binding TimeStr}" Width="92"/>
                        <DataGridTextColumn Header="来源 / PID" Binding="{Binding EnginePid}" Width="110"/>
                        <DataGridTextColumn Header="风险评估" Binding="{Binding RiskBadge}" Width="78"/>
                        <DataGridTextColumn Header="常驻 PowerShell 内部执行的脚本块或历史命令 (双击跳出独立窗口)" Binding="{Binding ScriptPreview}" Width="*"/>
                    </DataGrid.Columns>
                </DataGrid>
            </TabItem>

            <TabItem Header="👻 4. 孤儿僵尸进程 &amp; 死锁猎手">
                <DataGrid x:Name="GridOrphans" AutoGenerateColumns="False" IsReadOnly="True"
                          Background="#0B0F19" BorderThickness="0" GridLinesVisibility="Horizontal"
                          HorizontalGridLinesBrush="#1E293B" RowHeaderWidth="0" SelectionMode="Single" FontSize="12">
                    <DataGrid.Columns>
                        <DataGridTextColumn Header="发现时间" Binding="{Binding TimeStr}" Width="92"/>
                        <DataGridTextColumn Header="类型" Binding="{Binding TypeBadge}" Width="115"/>
                        <DataGridTextColumn Header="进程/锁名称" Binding="{Binding TargetName}" Width="160"/>
                        <DataGridTextColumn Header="占用端口 / 残留原因" Binding="{Binding Reason}" Width="220"/>
                        <DataGridTextColumn Header="详情 / 原始命令行" Binding="{Binding Detail}" Width="*"/>
                    </DataGrid.Columns>
                </DataGrid>
            </TabItem>
        </TabControl>

        <GridSplitter Grid.Row="3" Height="6" HorizontalAlignment="Stretch" VerticalAlignment="Center" Background="#1E293B" Cursor="SizeNS"/>

        <!-- 底部快速预览与实时输出分栏 -->
        <Grid x:Name="GridBottomDetail" Grid.Row="4">
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="1.35*" MinWidth="220"/>
                <ColumnDefinition Width="6"/>
                <ColumnDefinition Width="1*" MinWidth="180"/>
            </Grid.ColumnDefinitions>

            <Border Grid.Column="0" Background="#0F172A" BorderBrush="#334155" BorderThickness="1" CornerRadius="6" Padding="8">
                <DockPanel>
                    <TextBlock DockPanel.Dock="Top" Text="🔎 快速预览栏 (💡 双击上方表格任意行或按 Enter 键，立即跳出独立窗口单独查看该命令及关联文件改动)" Foreground="#60A5FA" FontWeight="Bold" Margin="0,0,0,4"/>
                    <TextBox x:Name="TxtDetail" Background="Transparent" Foreground="#E2E8F0" BorderThickness="0"
                             IsReadOnly="True" TextWrapping="Wrap" VerticalScrollBarVisibility="Auto"
                             FontFamily="Consolas, Microsoft YaHei UI" FontSize="11.5"
                             Text="💡 终极版操作体验：主窗口全程无需暂停。想单独细看某条命令时，直接【双击该行】或按【Enter】，即可跳出专属独立窗口（自带冻结/恢复/强杀/打开工作目录/导出 Markdown 取证单，并自动关联该命令运行期间修改的文件列表）！"/>
                </DockPanel>
            </Border>

            <GridSplitter Grid.Column="1" Width="6" HorizontalAlignment="Center" VerticalAlignment="Stretch" Background="#1E293B" Cursor="SizeWE"/>

            <Border Grid.Column="2" Background="#0F172A" BorderBrush="#334155" BorderThickness="1" CornerRadius="6" Padding="8">
                <DockPanel>
                    <TextBlock DockPanel.Dock="Top" Text="📄 实时事件 &amp; 输出流 ($env:TEMP\agent_live.log)" Foreground="#34D399" FontWeight="Bold" Margin="0,0,0,4"/>
                    <TextBox x:Name="TxtLiveLog" Background="Transparent" Foreground="#A7F3D0" BorderThickness="0"
                             IsReadOnly="True" TextWrapping="Wrap" VerticalScrollBarVisibility="Auto"
                             FontFamily="Consolas, Microsoft YaHei UI" FontSize="11"/>
                </DockPanel>
            </Border>
        </Grid>

        <!-- 底部状态说明 -->
        <TextBlock x:Name="TxtFooter" Grid.Row="5" Margin="2,5,0,0" Foreground="#64748B" FontSize="11"
                   Text="🛡️ 监控工作区: 加载中..."/>
    </Grid>
</Window>
"@

    $reader = New-Object System.Xml.XmlNodeReader $xaml
    $window = [Windows.Markup.XamlReader]::Load($reader)

    $workArea = [System.Windows.SystemParameters]::WorkArea
    if ($workArea.Width -gt 0 -and $workArea.Height -gt 0) {
        $window.Width  = [Math]::Min(1260, [Math]::Max(800, [Math]::Floor($workArea.Width * 0.87)))
        $window.Height = [Math]::Min(750,  [Math]::Max(500, [Math]::Floor($workArea.Height * 0.85)))
    }

    $StatusPulse         = $window.FindName("StatusPulse")
    $TxtStatusTitle      = $window.FindName("TxtStatusTitle")
    $TxtStats            = $window.FindName("TxtStats")
    $TxtHoverAnchorBadge = $window.FindName("TxtHoverAnchorBadge")
    $ChkCircuitBreaker   = $window.FindName("ChkCircuitBreaker")
    $ChkAutoFreeze       = $window.FindName("ChkAutoFreeze")
    $ChkTrayAlert        = $window.FindName("ChkTrayAlert")
    $ChkTopmost          = $window.FindName("ChkTopmost")
    $SliderOpacity       = $window.FindName("SliderOpacity")
    $BtnMiniMode         = $window.FindName("BtnMiniMode")
    $BorderToolbar       = $window.FindName("BorderToolbar")
    $CmbAgentChannel     = $window.FindName("CmbAgentChannel")
    $TxtFilter           = $window.FindName("TxtFilter")
    $BtnPopOut           = $window.FindName("BtnPopOut")
    $BtnFreezeAgent      = $window.FindName("BtnFreezeAgent")
    $BtnSuspend          = $window.FindName("BtnSuspend")
    $BtnResume           = $window.FindName("BtnResume")
    $BtnKill             = $window.FindName("BtnKill")
    $BtnRollbackPrev     = $window.FindName("BtnRollbackPrev")
    $BtnRollbackFile     = $window.FindName("BtnRollbackFile")
    $BtnCleanOrphans     = $window.FindName("BtnCleanOrphans")
    $BtnExport           = $window.FindName("BtnExport")
    $MainTabs            = $window.FindName("MainTabs")
    $GridProcesses       = $window.FindName("GridProcesses")
    $GridFiles           = $window.FindName("GridFiles")
    $GridScriptBlocks    = $window.FindName("GridScriptBlocks")
    $GridOrphans         = $window.FindName("GridOrphans")
    $RowDetailPanel      = $window.FindName("RowDetailPanel")
    $RowFooterPanel      = $window.FindName("RowFooterPanel")
    $GridBottomDetail    = $window.FindName("GridBottomDetail")
    $TxtDetail           = $window.FindName("TxtDetail")
    $TxtLiveLog          = $window.FindName("TxtLiveLog")
    $TxtFooter           = $window.FindName("TxtFooter")

    $ChkAutoFreeze.IsChecked = [bool]$AutoFreezeHighRisk
    if ($FilterAgent) { $TxtFilter.Text = $FilterAgent }

    $AgentChannels = New-Object System.Collections.ObjectModel.ObservableCollection[string]
    $AgentChannels.Add("🌐 全部 Agent 通道")
    $CmbAgentChannel.ItemsSource = $AgentChannels
    $CmbAgentChannel.SelectedIndex = 0

    $TrayIcon = New-Object System.Windows.Forms.NotifyIcon
    $TrayIcon.Icon = [System.Drawing.SystemIcons]::Shield
    $TrayIcon.Text = "AI Agent 哨兵舱 v8.0"
    $TrayIcon.Visible = $true
    $TrayIcon.Add_DoubleClick({
        $window.Show()
        $window.WindowState = [System.Windows.WindowState]::Normal
        $window.Activate() | Out-Null
    })

    $ProcCollection   = New-Object System.Collections.ObjectModel.ObservableCollection[AgentProcessRecordV8]
    $FileCollection   = New-Object System.Collections.ObjectModel.ObservableCollection[PSObject]
    $ScriptCollection = New-Object System.Collections.ObjectModel.ObservableCollection[PSObject]
    $OrphanCollection = New-Object System.Collections.ObjectModel.ObservableCollection[PSObject]

    $GridProcesses.ItemsSource    = $ProcCollection
    $GridFiles.ItemsSource        = $FileCollection
    $GridScriptBlocks.ItemsSource = $ScriptCollection
    $GridOrphans.ItemsSource      = $OrphanCollection

    $ProcView = [System.Windows.Data.CollectionViewSource]::GetDefaultView($ProcCollection)
    $UpdateViewFilter = {
        $kw = $TxtFilter.Text.Trim()
        $selectedAgent = [string]$CmbAgentChannel.SelectedItem
        $filterByAgent = ($selectedAgent -and $selectedAgent -ne "🌐 全部 Agent 通道")

        if (-not $filterByAgent -and [string]::IsNullOrWhiteSpace($kw)) {
            $ProcView.Filter = $null
        } else {
            $ProcView.Filter = [Predicate[object]]{
                param($row)
                if ($filterByAgent -and $row.AgentInstance -ne $selectedAgent) { return $false }
                if (-not [string]::IsNullOrWhiteSpace($kw)) {
                    return ("$($row.AgentInstance) $($row.ProcessDisplay) $($row.AncestryChain) $($row.CwdFull) $($row.FullCommand) $($row.DecodedText) $($row.TouchedFilesText)" -match $kw)
                }
                return $true
            }
        }
        $ProcView.Refresh()
    }

    $TxtFilter.Add_TextChanged($UpdateViewFilter)
    $CmbAgentChannel.Add_SelectionChanged($UpdateViewFilter)

    $resolvedPath = (Resolve-Path $WorkspacePath -ErrorAction SilentlyContinue).Path
    if (-not $resolvedPath) { $resolvedPath = $PWD.Path }
    $baselineCount = Initialize-WorkspaceSnapshot -RootPath $resolvedPath
    $privBadge = if ($Script:IsAdmin) { "🛡️ 管理员全量权限" } else { "🔓 标准用户权限" }
    $TxtFooter.Text = "$privBadge | PS v$($Script:PSMajorVersion) | 受保护工作区: $resolvedPath (💡 双击任意行或按 Enter 即弹出独立窗口，重复双击自动唤醒已有窗口)"
    $TxtLiveLog.AppendText("[$(Get-Date -Format 'HH:mm:ss')] ✅ v8.0 终极版就绪：支持进程➔文件改动因果归因、内存/CPU遥测、双击/Enter跳出独立窗口！`r`n")

    $WatcherCtx = Start-WorkspaceFileWatcher -RootPath $resolvedPath

    $psHistoryPath = Join-Path $env:APPDATA "Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
    $initHistoryLen = if (Test-Path $psHistoryPath) { (Get-Item $psHistoryPath).Length } else { 0 }

    $State = @{
        TickCounter         = [int]0
        IsMiniMode          = $false
        NormalWidth         = $window.Width
        NormalHeight        = $window.Height
        LastMouseAimTime    = [DateTime]::MinValue
        ActivePids          = @{}
        LatestTriggeredItem = $null
        HoverPendingQueue   = New-Object System.Collections.Generic.List[AgentProcessRecordV8]
        AgentFailures       = @{}
        KnownAgents         = @{}
        TotalCaptured       = [int]0
        FileChangesCount    = [int]0
        MaxFailuresLimit    = [int]$MaxConsecutiveFailures
        WorkspaceRoot       = $resolvedPath
        RecentSpawnTimes    = New-Object System.Collections.Generic.Queue[DateTime]
        LastEventRecordId   = [long]0
        PsHistoryPath       = $psHistoryPath
        LastPsHistoryOffset = [long]$initHistoryLen
        LogFilePath         = "$env:TEMP\agent_live.log"
        LastLogOffset       = [long]0
    }

    if (Test-Path $State.LogFilePath) {
        $State.LastLogOffset = (Get-Item $State.LogFilePath).Length
    }

    try {
        $latestEvt = Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -FilterXPath "*[System[(EventID=4104)]]" -MaxEvents 1 -ErrorAction Stop
        if ($latestEvt) { $State.LastEventRecordId = [long]$latestEvt.RecordId }
    } catch {}

    foreach ($p in [System.Diagnostics.Process]::GetProcesses()) {
        $State.ActivePids[[uint32]$p.Id] = @{ PreExisting = $true; Handle = [IntPtr]::Zero }
    }

    # 智能 2.5 秒鼠标移动瞄准感知：仅当鼠标在表格上移动瞄准时锁定 2.5 秒不插入新行，避免鼠标停在表上发呆时列表永久不更新
    $GridProcesses.Add_PreviewMouseMove({
        $State.LastMouseAimTime = [DateTime]::UtcNow
    })

    # 核心交互：双击任意行 / 按下 Enter 或 Space / 点击按钮 -> 立即跳出独立窗口（同一命令自动去重唤醒）
    $PopOutCurrentSelection = {
        if ($MainTabs.SelectedIndex -eq 0 -and $null -ne $GridProcesses.SelectedItem) {
            Open-CommandInspectorWindow -ProcessRecord $GridProcesses.SelectedItem -UniqueWindowKey "" -TitleText "" -StaticContent ""
        } elseif ($MainTabs.SelectedIndex -eq 1 -and $null -ne $GridFiles.SelectedItem) {
            $sel = $GridFiles.SelectedItem
            Open-CommandInspectorWindow -ProcessRecord $null -UniqueWindowKey "FILE_$($sel.TimeStr)_$($sel.RelativePath)" -TitleText "🗗 文件变更对比: $($sel.RelativePath)" -StaticContent $TxtDetail.Text
        } elseif ($MainTabs.SelectedIndex -eq 2 -and $null -ne $GridScriptBlocks.SelectedItem) {
            $sel = $GridScriptBlocks.SelectedItem
            Open-CommandInspectorWindow -ProcessRecord $null -UniqueWindowKey "SB_$($sel.TimeStr)_$($sel.EnginePid)" -TitleText "🗗 内存脚本块详情: $($sel.EnginePid)" -StaticContent $TxtDetail.Text
        } elseif ($MainTabs.SelectedIndex -eq 3 -and $null -ne $GridOrphans.SelectedItem) {
            $sel = $GridOrphans.SelectedItem
            Open-CommandInspectorWindow -ProcessRecord $null -UniqueWindowKey "ORP_$($sel.TargetName)" -TitleText "🗗 孤儿进程详情: $($sel.TargetName)" -StaticContent $TxtDetail.Text
        }
    }

    $GridProcesses.Add_MouseDoubleClick($PopOutCurrentSelection)
    $GridFiles.Add_MouseDoubleClick($PopOutCurrentSelection)
    $GridScriptBlocks.Add_MouseDoubleClick($PopOutCurrentSelection)
    $GridOrphans.Add_MouseDoubleClick($PopOutCurrentSelection)
    $BtnPopOut.Add_Click($PopOutCurrentSelection)

    $window.Add_PreviewKeyDown({
        param($sender, $e)
        if ($e.Key -eq [System.Windows.Input.Key]::Return -and (-not $TxtFilter.IsKeyboardFocused)) {
            $e.Handled = $true
            & $PopOutCurrentSelection
        }
    })

    $BtnMiniMode.Add_Click({
        if (-not $State.IsMiniMode) {
            $State.NormalWidth  = $window.Width
            $State.NormalHeight = $window.Height
            $State.IsMiniMode   = $true
            $BorderToolbar.Visibility    = [System.Windows.Visibility]::Collapsed
            $GridBottomDetail.Visibility = [System.Windows.Visibility]::Collapsed
            $TxtFooter.Visibility        = [System.Windows.Visibility]::Collapsed
            $RowDetailPanel.Height       = New-Object System.Windows.GridLength(0)
            $window.Width  = 500
            $window.Height = 250
            $wa = [System.Windows.SystemParameters]::WorkArea
            $window.Left = $wa.Right - $window.Width - 16
            $window.Top  = $wa.Top + 16
            $BtnMiniMode.Content = "🗖 展开全景"
        } else {
            $State.IsMiniMode = $false
            $BorderToolbar.Visibility    = [System.Windows.Visibility]::Visible
            $GridBottomDetail.Visibility = [System.Windows.Visibility]::Visible
            $TxtFooter.Visibility        = [System.Windows.Visibility]::Visible
            $RowDetailPanel.Height       = New-Object System.Windows.GridLength(185)
            $window.Width  = $State.NormalWidth
            $window.Height = $State.NormalHeight
            $BtnMiniMode.Content = "🗕 迷你雷达"
        }
    })

    $ChkTopmost.Add_Click({ $window.Topmost = [bool]$ChkTopmost.IsChecked })
    $SliderOpacity.Add_ValueChanged({ $window.Opacity = $SliderOpacity.Value })

    $GridProcesses.Add_SelectionChanged({
        $sel = $GridProcesses.SelectedItem
        if ($null -ne $sel) {
            $TxtDetail.Text = $sel.FormatFullDetail()
        }
    })

    $GridFiles.Add_SelectionChanged({
        $sel = $GridFiles.SelectedItem
        if ($null -ne $sel) {
            $compareTarget = if ($sel.PrevVersionPath -and (Test-Path $sel.PrevVersionPath)) { $sel.PrevVersionPath } else { $sel.BackupPath }
            $diffText = Get-FileDiffPreview -SnapshotFile $compareTarget -CurrentFile $sel.FullPath
            $TxtDetail.Text = @(
                "【文件变更时间】 $($sel.TimeStr)   |   【动作】 $($sel.ActionBadge)",
                "【归因触发进程】 $($sel.TriggerProcess)",
                "【文件完整路径】 $($sel.FullPath)",
                "【双轨快照状态】 $($sel.BackupStatus)",
                "==================== 快照版本 vs 当前文件 Diff 对比 ====================",
                $diffText
            ) -join "`r`n"
        }
    })

    $GridScriptBlocks.Add_SelectionChanged({
        $sel = $GridScriptBlocks.SelectedItem
        if ($null -ne $sel) {
            $TxtDetail.Text = @(
                "【捕获时间】 $($sel.TimeStr)   |   【来源 / PID】 $($sel.EnginePid)   |   【风险】 $($sel.RiskBadge)",
                "==================== 常驻终端内部执行的完整脚本块 / 历史指令 ====================",
                $sel.FullScript
            ) -join "`r`n"
        }
    })

    $GridOrphans.Add_SelectionChanged({
        $sel = $GridOrphans.SelectedItem
        if ($null -ne $sel) {
            $TxtDetail.Text = @(
                "【孤儿/锁对象】 $($sel.TargetName)   |   【类型】 $($sel.TypeBadge)",
                "【残留原因与端口】 $($sel.Reason)",
                "==================== 详情 / 原始命令行 ====================",
                $sel.Detail
            ) -join "`r`n"
        }
    })

    $BtnFreezeAgent.Add_Click({
        $targetAgent = $null
        if ($null -ne $GridProcesses.SelectedItem) {
            $targetAgent = $GridProcesses.SelectedItem.AgentInstance
        } elseif ($CmbAgentChannel.SelectedIndex -gt 0) {
            $targetAgent = [string]$CmbAgentChannel.SelectedItem
        }

        $frozen = 0
        $keys = @($State.ActivePids.Keys)
        foreach ($k in $keys) {
            $entry = $State.ActivePids[$k]
            if ($null -ne $entry -and (-not $entry.PreExisting) -and ($null -ne $entry.Item) -and (-not $entry.Item.IsSuspended)) {
                if (-not $targetAgent -or $entry.Item.AgentInstance -eq $targetAgent) {
                    if (Suspend-ProcessTree -RootPid ([uint32]$k)) {
                        $entry.Item.IsSuspended = $true
                        $entry.Item.StateText = "⏸️ 树已冻结"
                        $frozen++
                    }
                }
            }
        }
        $scopeDesc = if ($targetAgent) { "Agent [$targetAgent]" } else { "全部活跃 Agent" }
        $TxtLiveLog.AppendText("[$(Get-Date -Format 'HH:mm:ss')] ❄️ 已针对 $scopeDesc 递归冻结 $frozen 棵后台进程树！`r`n")
        $TxtLiveLog.ScrollToEnd()
    })

    $BtnSuspend.Add_Click({
        $sel = $GridProcesses.SelectedItem
        if ($null -eq $sel -or $sel.IsSuspended) { return }
        if (Suspend-ProcessTree -RootPid ([uint32]$sel.Pid)) {
            $sel.IsSuspended = $true
            $sel.StateText = "⏸️ 树已冻结"
            $TxtDetail.Text = $sel.FormatFullDetail()
        }
    })

    $BtnResume.Add_Click({
        $sel = $GridProcesses.SelectedItem
        if ($null -eq $sel) { return }
        if (Resume-ProcessTree -RootPid ([uint32]$sel.Pid)) {
            $sel.IsSuspended = $false
            $sel.StateText = "⚡ 运行中"
            $TxtDetail.Text = $sel.FormatFullDetail()
        }
    })

    $BtnKill.Add_Click({
        if ($MainTabs.SelectedIndex -eq 3 -and $null -ne $GridOrphans.SelectedItem) {
            $orp = $GridOrphans.SelectedItem
            if ($orp.RawPid -gt 0 -and (Stop-ProcessTree -TargetPid ([uint32]$orp.RawPid))) {
                $orp.TypeBadge = "🛑 已清理"
                $GridOrphans.Items.Refresh()
                $TxtLiveLog.AppendText("[$(Get-Date -Format 'HH:mm:ss')] 🛑 已清理孤儿进程树 PID: $($orp.RawPid)`r`n")
                $TxtLiveLog.ScrollToEnd()
            }
            return
        }
        $sel = $GridProcesses.SelectedItem
        if ($null -ne $sel -and (Stop-ProcessTree -TargetPid ([uint32]$sel.Pid))) {
            $sel.IsSuspended = $false
            $sel.StateText = "🛑 已强杀"
            $TxtDetail.Text = $sel.FormatFullDetail()
        }
    })

    $BtnRollbackPrev.Add_Click({
        $sel = $GridFiles.SelectedItem
        if ($null -eq $sel) {
            [System.Windows.MessageBox]::Show("请先切换到【2. 文件篡改哨兵】并选中要回退的文件行。", "提示", "OK", "Information") | Out-Null
            return
        }
        $snap = if ($sel.PrevVersionPath -and (Test-Path $sel.PrevVersionPath)) { $sel.PrevVersionPath } else { $sel.BackupPath }
        if ($snap -and (Test-Path $snap)) {
            $WatcherCtx.SuppressUntil = [DateTime]::UtcNow.AddMilliseconds(800)
            $targetDir = Split-Path $sel.FullPath -Parent
            if (-not (Test-Path $targetDir)) { New-Item -ItemType Directory -Path $targetDir -Force | Out-Null }
            Copy-Item -Path $snap -Destination $sel.FullPath -Force
            $sel.BackupStatus = "✅ 已回退至修改前上一版本"
            $GridFiles.Items.Refresh()
            $TxtDetail.Text = "✅ 已将 $($sel.RelativePath) 恢复至本次修改前的上一版本！"
            $TxtLiveLog.AppendText("[$(Get-Date -Format 'HH:mm:ss')] ⏪ 已将文件回退至上一版本: $($sel.RelativePath)`r`n")
            $TxtLiveLog.ScrollToEnd()
        } else {
            [System.Windows.MessageBox]::Show("该文件暂无可用的上一版本快照。", "提示", "OK", "Information") | Out-Null
        }
    })

    $BtnRollbackFile.Add_Click({
        $sel = $GridFiles.SelectedItem
        if ($null -eq $sel) {
            [System.Windows.MessageBox]::Show("请先切换到【2. 文件篡改哨兵】并选中要还原的文件行。", "提示", "OK", "Information") | Out-Null
            return
        }
        $WatcherCtx.SuppressUntil = [DateTime]::UtcNow.AddMilliseconds(800)
        if ($sel.BackupPath -and (Test-Path $sel.BackupPath)) {
            $targetDir = Split-Path $sel.FullPath -Parent
            if (-not (Test-Path $targetDir)) { New-Item -ItemType Directory -Path $targetDir -Force | Out-Null }
            Copy-Item -Path $sel.BackupPath -Destination $sel.FullPath -Force
            $sel.BackupStatus = "✅ 已成功还原至初始基线"
            $GridFiles.Items.Refresh()
            $TxtDetail.Text = "✅ 已成功将 $($sel.RelativePath) 彻底恢复至监控启动时的初始基线版本！"
            $TxtLiveLog.AppendText("[$(Get-Date -Format 'HH:mm:ss')] ⏮️ 已还原文件至初始基线: $($sel.RelativePath)`r`n")
            $TxtLiveLog.ScrollToEnd()
        } else {
            $ans = [System.Windows.MessageBox]::Show("该文件是会话期间新建的文件（监控启动时不存在），是否直接删除该新建文件？`n$($sel.FullPath)", "新建文件清理确认", "YesNo", "Question")
            if ($ans -eq "Yes" -and (Test-Path $sel.FullPath)) {
                $WatcherCtx.SuppressUntil = [DateTime]::UtcNow.AddMilliseconds(800)
                Remove-Item -Path $sel.FullPath -Force
                $sel.BackupStatus = "🗑️ 已删除新建文件"
                $GridFiles.Items.Refresh()
            }
        }
    })

    $BtnCleanOrphans.Add_Click({
        $MainTabs.SelectedIndex = 3
        $OrphanCollection.Clear()
        $orphans = Find-OrphanProcesses
        foreach ($o in $orphans) {
            $OrphanCollection.Add([PSCustomObject]@{
                TimeStr    = (Get-Date).ToString("HH:mm:ss")
                TypeBadge  = "👻 孤儿进程"
                TargetName = "$($o.Name) (PID: $($o.Pid))"
                Reason     = "父进程($($o.DeadParent))已退出 | $($o.NetPorts)"
                Detail     = $o.CommandLine
                RawPid     = [uint32]$o.Pid
            })
        }
        $gitLock = Join-Path $State.WorkspaceRoot ".git\index.lock"
        if (Test-Path $gitLock) {
            $WatcherCtx.SuppressUntil = [DateTime]::UtcNow.AddMilliseconds(800)
            Remove-Item -Path $gitLock -Force -ErrorAction SilentlyContinue
            $OrphanCollection.Add([PSCustomObject]@{
                TimeStr    = (Get-Date).ToString("HH:mm:ss")
                TypeBadge  = "🔓 已除死锁"
                TargetName = ".git\index.lock"
                Reason     = "已自动清除残留的 Git 索引锁文件"
                Detail     = $gitLock
                RawPid     = [uint32]0
            })
        }
        $TxtLiveLog.AppendText("[$(Get-Date -Format 'HH:mm:ss')] 🧹 扫描完成：发现 $($orphans.Count) 个孤儿进程。`r`n")
        $TxtLiveLog.ScrollToEnd()

        if ($orphans.Count -gt 0) {
            $ans = [System.Windows.MessageBox]::Show("发现 $($orphans.Count) 个父进程已退出的后台孤儿进程，是否立即全部清理？", "清理孤儿进程确认", "YesNo", "Warning")
            if ($ans -eq "Yes") {
                $killed = 0
                foreach ($item in $OrphanCollection) {
                    if ($item.RawPid -gt 0 -and (Stop-ProcessTree -TargetPid $item.RawPid)) {
                        $item.TypeBadge = "🛑 已清理"
                        $killed++
                    }
                }
                $GridOrphans.Items.Refresh()
                $TxtLiveLog.AppendText("[$(Get-Date -Format 'HH:mm:ss')] ✅ 已批量清理 $killed 个孤儿进程！`r`n")
                $TxtLiveLog.ScrollToEnd()
            }
        }
    })

    $BtnExport.Add_Click({
        $exportPath = Join-Path ([Environment]::GetFolderPath("Desktop")) ("Agent_Sentinel_Report_" + (Get-Date -Format "yyyyMMdd_HHmmss") + ".json")
        @{
            GeneratedAt  = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            Workspace    = $State.WorkspaceRoot
            Processes    = $ProcCollection
            FileChanges  = $FileCollection
            ScriptBlocks = $ScriptCollection
        } | ConvertTo-Json -Depth 4 | Set-Content -Path $exportPath -Encoding UTF8
        [System.Windows.MessageBox]::Show("全栈审计报告已导出至桌面：`n$exportPath", "导出成功", "OK", "Information") | Out-Null
    })

    # ========================================================================
    # 主定时器循环（2.5秒智能瞄准防移位 + 因果关联挂载 + 内存/CPU 遥测）
    # ========================================================================
    $timer = New-Object System.Windows.Threading.DispatcherTimer
    $timer.Interval = [TimeSpan]::FromMilliseconds($PollIntervalMs)

    $timer.Add_Tick({
        $State.TickCounter++
        $now = Get-Date
        $utcNow = [DateTime]::UtcNow

        # 仅当鼠标在表格上移动瞄准的 2.5 秒窗口期内冻结顶部行插入，超过 2.5 秒静止或移出表格立即无感刷入
        $isAiming = $GridProcesses.IsMouseOver -and (($utcNow - $State.LastMouseAimTime).TotalSeconds -lt 2.5)
        if ($isAiming) {
            $TxtHoverAnchorBadge.Text = "🎯 瞄准防移位中 (暂存 $($State.HoverPendingQueue.Count) 条)"
            $TxtHoverAnchorBadge.Visibility = [System.Windows.Visibility]::Visible
        } else {
            $TxtHoverAnchorBadge.Visibility = [System.Windows.Visibility]::Collapsed
            if ($State.HoverPendingQueue.Count -gt 0) {
                foreach ($pendingItem in $State.HoverPendingQueue) {
                    $ProcCollection.Insert(0, $pendingItem)
                    while ($ProcCollection.Count -gt 500) { $ProcCollection.RemoveAt($ProcCollection.Count - 1) }
                }
                $State.HoverPendingQueue.Clear()
            }
        }

        $fastProcs = [System.Diagnostics.Process]::GetProcesses()
        $currentWatchedPids = @{}
        $fastProcMap = @{}
        $newCandidatePids = New-Object System.Collections.Generic.List[uint32]

        foreach ($fp in $fastProcs) {
            $fPid = [uint32]$fp.Id
            if ($fPid -eq $PID) { continue }
            $pNameLower = $fp.ProcessName.ToLower()
            if (-not $Script:WatchedProcessNames.ContainsKey($pNameLower)) { continue }

            $currentWatchedPids[$fPid] = $true
            $fastProcMap[$fPid] = $fp
            if (-not $State.ActivePids.ContainsKey($fPid)) {
                $newCandidatePids.Add($fPid)
            }
        }

        if ($newCandidatePids.Count -gt 0) {
            $cimMap = Query-CimProcessesByPids -PidList $newCandidatePids

            foreach ($newPid in $newCandidatePids) {
                if (-not $cimMap.ContainsKey($newPid)) {
                    $State.ActivePids[$newPid] = @{ PreExisting = $true; Handle = [IntPtr]::Zero }
                    continue
                }
                $proc = $cimMap[$newPid]
                $ancInfo = Get-ProcessAncestryAndAgent -StartParentPid ([uint32]$proc.ParentProcessId)
                $ancestry = $ancInfo.ChainString
                $agentInst = $ancInfo.AgentInstance
                $cmdLine = if ($proc.CommandLine) { $proc.CommandLine.Trim() } else { "(无命令行参数 - 常驻交互式管道)" }

                if (-not $State.KnownAgents.ContainsKey($agentInst)) {
                    $State.KnownAgents[$agentInst] = $true
                    $State.AgentFailures[$agentInst] = [int]0
                    $AgentChannels.Add($agentInst)
                }

                $liveCwd = Resolve-ProcessCwdSmart -TargetPid $newPid -CmdLine $cmdLine -DefaultWorkspace $State.WorkspaceRoot
                $cwdShort = if ($liveCwd) { Split-Path $liveCwd -Leaf } else { "(未知/已退)" }
                if (-not $cwdShort -and $liveCwd) { $cwdShort = $liveCwd }

                $hProc = [SentinelNativeApiV8]::OpenProcess([SentinelNativeApiV8]::PROCESS_QUERY_LIMITED_INFORMATION, $false, $newPid)
                $decoded = Decode-AgentCommand -CmdLine $cmdLine
                $risk = Evaluate-CommandRisk -CmdLine $cmdLine -DecodedText $decoded
                $netInfo = [SentinelNativeApiV8]::GetFastTcpSummary($newPid)
                $resText = if ($fastProcMap.ContainsKey($newPid)) { Get-ProcessResourceSummary -LiveProc $fastProcMap[$newPid] } else { "-" }

                $State.RecentSpawnTimes.Enqueue($now)
                while ($State.RecentSpawnTimes.Count -gt 0 -and ($now - $State.RecentSpawnTimes.Peek()).TotalSeconds -gt 20) {
                    [void]$State.RecentSpawnTimes.Dequeue()
                }

                $agentFailCount = [int]$State.AgentFailures[$agentInst]
                $initialState = "⚡ 运行中"
                $isSuspended = $false
                $shouldFreeze = ($risk.Score -ge 3 -and $ChkAutoFreeze.IsChecked) -or
                                ($ChkCircuitBreaker.IsChecked -and ($agentFailCount -ge $State.MaxFailuresLimit -or $State.RecentSpawnTimes.Count -gt 18))

                if ($shouldFreeze) {
                    if (Suspend-ProcessTree -RootPid $newPid) {
                        $isSuspended = $true
                        $initialState = if ($risk.Score -ge 3) { "⏸️ 高危已冻结" } else { "⏸️ 熔断已冻结" }
                        $TxtLiveLog.AppendText("[$($now.ToString('HH:mm:ss'))] 🚨 自动防御冻结 [$agentInst] 进程树: $($proc.Name) (PID: $newPid)`r`n")
                        $TxtLiveLog.ScrollToEnd()

                        if ($ChkTrayAlert.IsChecked) {
                            [System.Media.SystemSounds]::Exclamation.Play()
                            $TrayIcon.ShowBalloonTip(4000, "🚨 [$agentInst] 高危行为已冻结", "进程: $($proc.Name) (PID: $newPid)`n原因: $($risk.Reason)", [System.Windows.Forms.ToolTipIcon]::Warning)
                        }
                    }
                }

                $preview = if ($decoded) { "🔓 " + ($decoded -replace "\r?\n", " ") } else { $cmdLine }
                if ($preview.Length -gt 135) { $preview = $preview.Substring(0, 135) + "..." }

                $parentPidVal = [uint32]$proc.ParentProcessId
                if ($State.ActivePids.ContainsKey($parentPidVal) -and (-not $State.ActivePids[$parentPidVal].PreExisting)) {
                    $parentRecord = $State.ActivePids[$parentPidVal].Item
                    if ($null -ne $parentRecord) {
                        $childTag = "$($proc.Name)($newPid)"
                        if ($parentRecord.ChildProcsText -eq "无派生子进程") {
                            $parentRecord.ChildProcsText = $childTag
                        } else {
                            $parentRecord.ChildProcsText = "$($parentRecord.ChildProcsText), $childTag"
                        }
                    }
                }

                $timeFormatted = $now.ToString("HH:mm:ss.fff")
                $item = New-Object AgentProcessRecordV8 -Property @{
                    UniqueKey      = "PROC_${newPid}_${timeFormatted}"
                    Pid            = $newPid
                    TimeStr        = $timeFormatted
                    AgentInstance  = $agentInst
                    StateText      = $initialState
                    IsSuspended    = $isSuspended
                    RiskBadge      = $risk.Badge
                    RiskReason     = $risk.Reason
                    ProcessDisplay = "$($proc.Name) ($newPid)"
                    AncestryChain  = $ancestry
                    CwdDisplay     = $cwdShort
                    CwdFull        = if ($liveCwd) { $liveCwd } else { "(未能从 PEB 或命令行提取 CWD)" }
                    CommandPreview = $preview
                    FullCommand    = $cmdLine
                    DecodedText    = $decoded
                    ResultText     = "运行中..."
                    ResourceUsage  = $resText
                    NetSummary     = $netInfo
                    StartTime      = $now
                }

                if ($isAiming) {
                    $State.HoverPendingQueue.Add($item)
                } else {
                    $ProcCollection.Insert(0, $item)
                    while ($ProcCollection.Count -gt 500) { $ProcCollection.RemoveAt($ProcCollection.Count - 1) }
                }

                $State.LatestTriggeredItem = $item
                $State.TotalCaptured++
                $State.ActivePids[$newPid] = @{ PreExisting = $false; Handle = $hProc; Item = $item }
            }
        }

        # 每 4 个 Tick 原地更新活跃进程的耗时、内存/CPU 与双栈端口
        if (($State.TickCounter % 4) -eq 0) {
            $activeKeys = @($State.ActivePids.Keys)
            foreach ($k in $activeKeys) {
                $entry = $State.ActivePids[$k]
                if ($null -ne $entry -and (-not $entry.PreExisting) -and ($null -ne $entry.Item)) {
                    $elapsed = ($now - $entry.Item.StartTime).TotalSeconds
                    $entry.Item.ResultText = ("{0:N1}s (运行中)" -f $elapsed)
                    if ($fastProcMap.ContainsKey([uint32]$k)) {
                        $entry.Item.ResourceUsage = Get-ProcessResourceSummary -LiveProc $fastProcMap[[uint32]$k]
                    }
                    if (-not $entry.Item.NetSummary -and $elapsed -gt 0.4) {
                        $entry.Item.NetSummary = [SentinelNativeApiV8]::GetFastTcpSummary([uint32]$k)
                    }
                }
            }
            if ($MainTabs.SelectedIndex -eq 0 -and $null -ne $GridProcesses.SelectedItem) {
                $sel = $GridProcesses.SelectedItem
                if ($State.ActivePids.ContainsKey($sel.Pid)) {
                    $TxtDetail.Text = $sel.FormatFullDetail()
                }
            }
        }

        $exited = @($State.ActivePids.Keys | Where-Object { -not $currentWatchedPids.ContainsKey($_) })
        foreach ($oldPid in $exited) {
            $entry = $State.ActivePids[$oldPid]
            $State.ActivePids.Remove($oldPid)

            if ($entry.Handle -and $entry.Handle -ne [IntPtr]::Zero) {
                $exitCode = [SentinelNativeApiV8]::TryGetExitCode($entry.Handle)
                [void][SentinelNativeApiV8]::CloseHandle($entry.Handle)
                $entry.Handle = [IntPtr]::Zero
            } else {
                $exitCode = $null
            }

            if (-not $entry.PreExisting -and $null -ne $entry.Item) {
                $duration = ($now - $entry.Item.StartTime).TotalSeconds
                $agKey = $entry.Item.AgentInstance
                $entry.Item.IsSuspended = $false

                if ($null -ne $exitCode) {
                    if ($exitCode -eq 0) {
                        $entry.Item.StateText = "✅ 已完成"
                        $entry.Item.ResultText = ("{0:N2}s (Code: 0)" -f $duration)
                        $State.AgentFailures[$agKey] = [int]0
                    } else {
                        $entry.Item.StateText = "❌ 报错退出"
                        $entry.Item.ResultText = ("{0:N2}s (Code: $exitCode)" -f $duration)
                        $State.AgentFailures[$agKey] = [int]$State.AgentFailures[$agKey] + 1
                        $currFails = $State.AgentFailures[$agKey]
                        if ($currFails -ge $State.MaxFailuresLimit) {
                            $TxtLiveLog.AppendText("[$($now.ToString('HH:mm:ss'))] ⚠️ 警告：[$agKey] 已连续失败 $currFails 次，触发该 Agent 独立熔断预警！`r`n")
                            $TxtLiveLog.ScrollToEnd()
                            if ($ChkTrayAlert.IsChecked) {
                                $TrayIcon.ShowBalloonTip(3500, "⚡ [$agKey] 疑似陷入报错死循环", "该 Agent 后台命令已连续失败 $currFails 次，已启动独立熔断保护。", [System.Windows.Forms.ToolTipIcon]::Error)
                            }
                        }
                    }
                } else {
                    $entry.Item.StateText = "⏹️ 已结束"
                    $entry.Item.ResultText = ("{0:N2}s" -f $duration)
                }

                if ($MainTabs.SelectedIndex -eq 0 -and $GridProcesses.SelectedItem -eq $entry.Item) {
                    $TxtDetail.Text = $entry.Item.FormatFullDetail()
                }
            }
        }

        # 消费文件变更队列，并自动执行【进程 ➔ 文件改动】因果时间轴归因绑定
        $fileEvt = $null
        while ($WatcherCtx.Queue.TryDequeue([ref]$fileEvt)) {
            $rel = Get-RelativeWorkspacePath -BasePath $State.WorkspaceRoot -FullPath $fileEvt.FullPath
            $baseBackup = Join-Path $Script:BackupRoot ("Baseline\" + $rel)
            $workCopy   = Join-Path $Script:BackupRoot ("WorkingCopy\" + $rel)
            $prevSnap   = Join-Path $Script:BackupRoot ("PrevVersion\" + $rel)

            if (Test-Path $workCopy) {
                $prevDir = Split-Path $prevSnap -Parent
                if (-not (Test-Path $prevDir)) { New-Item -ItemType Directory -Path $prevDir -Force | Out-Null }
                Copy-Item -Path $workCopy -Destination $prevSnap -Force -ErrorAction SilentlyContinue
            }
            if ((Test-Path $fileEvt.FullPath -PathType Leaf) -and ((Get-Item $fileEvt.FullPath).Length -lt 2MB)) {
                $workDir = Split-Path $workCopy -Parent
                if (-not (Test-Path $workDir)) { New-Item -ItemType Directory -Path $workDir -Force | Out-Null }
                Copy-Item -Path $fileEvt.FullPath -Destination $workCopy -Force -ErrorAction SilentlyContinue
            }

            $hasBase = Test-Path $baseBackup
            $hasPrev = Test-Path $prevSnap
            $statusStr = if ($hasBase -and $hasPrev) {
                "🛡️ 基线 + 上一版本双快照就绪"
            } elseif ($hasBase) {
                "🛡️ 初始基线快照就绪"
            } elseif ($hasPrev) {
                "🔄 新建文件 (已保存上一版本快照)"
            } else {
                "🆕 新建文件 (首次写入已归档)"
            }

            $badge = switch ($fileEvt.ChangeType) {
                "Created" { "🟢 新建文件" }
                "Deleted" { "🔴 删除文件" }
                "Renamed" { "🟡 重命名" }
                "GitLock" { "🔒 Git锁生成" }
                default   { "📝 修改内容" }
            }

            # 因果关联：查找当前正在运行的后台命令（或最近 2 秒内刚触发的命令），将此文件变更自动挂载到该命令记录上
            $correlatedProc = $null
            foreach ($actEntry in $State.ActivePids.Values) {
                if (-not $actEntry.PreExisting -and $null -ne $actEntry.Item) {
                    $correlatedProc = $actEntry.Item
                    break
                }
            }
            if ($null -eq $correlatedProc -and $null -ne $State.LatestTriggeredItem) {
                if (($now - $State.LatestTriggeredItem.StartTime).TotalSeconds -lt 2.5) {
                    $correlatedProc = $State.LatestTriggeredItem
                }
            }

            $triggerDesc = "⚡ 宿主直接写入 (Node/Python API)"
            if ($null -ne $correlatedProc) {
                $triggerDesc = "$($correlatedProc.AgentInstance) ➔ $($correlatedProc.ProcessDisplay)"
                $fileTag = "$badge $rel"
                if ($correlatedProc.TouchedFilesText -eq "运行期间暂未触发工作区文件修改") {
                    $correlatedProc.TouchedFilesText = $fileTag
                } elseif ($correlatedProc.TouchedFilesText.Length -lt 600 -and (-not $correlatedProc.TouchedFilesText.Contains($rel))) {
                    $correlatedProc.TouchedFilesText = "$($correlatedProc.TouchedFilesText); $fileTag"
                }
            }

            $FileCollection.Insert(0, [PSCustomObject]@{
                TimeStr         = $fileEvt.TimeStr
                ActionBadge     = $badge
                TriggerProcess  = $triggerDesc
                RelativePath    = $rel
                BackupStatus    = $statusStr
                FullPath        = $fileEvt.FullPath
                BackupPath      = if ($hasBase) { $baseBackup } else { "" }
                PrevVersionPath = if ($hasPrev) { $prevSnap } else { "" }
            })
            while ($FileCollection.Count -gt 500) { $FileCollection.RemoveAt($FileCollection.Count - 1) }
            $State.FileChangesCount++
        }

        if (($State.TickCounter % 10) -eq 0) {
            try {
                $xpath = "*[System[(EventID=4104) and (EventRecordID > $($State.LastEventRecordId))]]"
                $evts = Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -FilterXPath $xpath -MaxEvents 15 -ErrorAction Stop |
                    Sort-Object RecordId
                foreach ($ev in $evts) {
                    $State.LastEventRecordId = [long]$ev.RecordId
                    if ($ev.ProcessId -eq $PID) { continue }
                    $scriptText = if ($ev.Properties.Count -ge 3) { [string]$ev.Properties[2].Value } else { $ev.Message }
                    if ([string]::IsNullOrWhiteSpace($scriptText) -or $scriptText -match '^\s*(prompt|Out-Default)\s*$') { continue }

                    $risk = Evaluate-CommandRisk -CmdLine $scriptText -DecodedText ""
                    $shortScript = ($scriptText -replace "\r?\n", " ").Trim()
                    if ($shortScript.Length -gt 140) { $shortScript = $shortScript.Substring(0, 140) + "..." }

                    $ScriptCollection.Insert(0, [PSCustomObject]@{
                        TimeStr       = $ev.TimeCreated.ToString("HH:mm:ss.fff")
                        EnginePid     = "4104 (PID:$($ev.ProcessId))"
                        RiskBadge     = $risk.Badge
                        ScriptPreview = $shortScript
                        FullScript    = $scriptText
                    })
                    while ($ScriptCollection.Count -gt 500) { $ScriptCollection.RemoveAt($ScriptCollection.Count - 1) }
                }
            } catch {}

            if (Test-Path $State.PsHistoryPath) {
                $hItem = Get-Item $State.PsHistoryPath
                if ($hItem.Length -lt $State.LastPsHistoryOffset) { $State.LastPsHistoryOffset = 0 }
                if ($hItem.Length -gt $State.LastPsHistoryOffset) {
                    try {
                        $hFs = [System.IO.File]::Open($State.PsHistoryPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
                        [void]$hFs.Seek($State.LastPsHistoryOffset, [System.IO.SeekOrigin]::Begin)
                        $hSr = New-Object System.IO.StreamReader($hFs, [System.Text.Encoding]::UTF8)
                        $newHist = $hSr.ReadToEnd()
                        $State.LastPsHistoryOffset = $hFs.Position
                        $hSr.Close()
                        $hFs.Close()
                        foreach ($hLine in ($newHist -split "\r?\n")) {
                            if (-not [string]::IsNullOrWhiteSpace($hLine)) {
                                $hRisk = Evaluate-CommandRisk -CmdLine $hLine -DecodedText ""
                                $ScriptCollection.Insert(0, [PSCustomObject]@{
                                    TimeStr       = (Get-Date).ToString("HH:mm:ss.fff")
                                    EnginePid     = "PSReadLine 历史"
                                    RiskBadge     = $hRisk.Badge
                                    ScriptPreview = $hLine.Trim()
                                    FullScript    = $hLine.Trim()
                                })
                            }
                        }
                    } catch {}
                }
            }
        }

        $activeEntries = @($State.ActivePids.Values | Where-Object { -not $_.PreExisting })
        $runningCount = $activeEntries.Count
        $activeAgentCount = @($activeEntries | ForEach-Object { $_.Item.AgentInstance } | Select-Object -Unique).Count
        $anyTripped = @($State.AgentFailures.Values | Where-Object { $_ -ge $State.MaxFailuresLimit }).Count -gt 0

        if ($anyTripped) {
            $StatusPulse.Fill = [System.Windows.Media.Brushes]::Red
            $TxtStatusTitle.Text = "🚨 警告：存在 Agent 触发连续报错熔断"
            $TxtStatusTitle.Foreground = [System.Windows.Media.Brushes]::Red
        } elseif ($runningCount -gt 0) {
            $StatusPulse.Fill = [System.Windows.Media.Brushes]::Orange
            $TxtStatusTitle.Text = "⚡ $activeAgentCount 个 Agent 正在并发执行 ($runningCount 进程)"
            $TxtStatusTitle.Foreground = [System.Windows.Media.Brushes]::Orange
        } else {
            $StatusPulse.Fill = [System.Windows.Media.Brushes]::MediumSeaGreen
            $TxtStatusTitle.Text = "四维哨兵待命中"
            $TxtStatusTitle.Foreground = [System.Windows.Media.Brushes]::MediumSeaGreen
        }
        $TxtStats.Text = "  |  并发Agent: $($State.KnownAgents.Count)  |  活跃进程: $runningCount  |  累计命令: $($State.TotalCaptured)  |  文件变更: $($State.FileChangesCount)  |  已开独立窗: $($Script:OpenInspectorWindows.Count)"

        if (Test-Path $State.LogFilePath) {
            $fItem = Get-Item $State.LogFilePath
            if ($fItem.Length -lt $State.LastLogOffset) { $State.LastLogOffset = 0 }
            if ($fItem.Length -gt $State.LastLogOffset) {
                try {
                    $fs = [System.IO.File]::Open($State.LogFilePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
                    [void]$fs.Seek($State.LastLogOffset, [System.IO.SeekOrigin]::Begin)
                    $sr = New-Object System.IO.StreamReader($fs, [System.Text.Encoding]::UTF8)
                    $chunk = $sr.ReadToEnd()
                    $State.LastLogOffset = $fs.Position
                    $sr.Close()
                    $fs.Close()
                    if ($chunk) {
                        $TxtLiveLog.AppendText($chunk)
                        $TxtLiveLog.ScrollToEnd()
                    }
                } catch {}
            }
        }
    })

    $window.Add_Closed({
        $timer.Stop()
        # 主窗口关闭时安全销毁所有已弹出的独立子窗口
        $openWins = @($Script:OpenInspectorWindows.Values)
        foreach ($cw in $openWins) {
            try { $cw.Close() } catch {}
        }
        $Script:OpenInspectorWindows.Clear()
        $TrayIcon.Visible = $false
        $TrayIcon.Dispose()
        Stop-WorkspaceFileWatcher -SyncContext $WatcherCtx
        foreach ($v in $State.ActivePids.Values) {
            if ($v.Handle -and $v.Handle -ne [IntPtr]::Zero) {
                [void][SentinelNativeApiV8]::CloseHandle($v.Handle)
            }
        }
    })

    $timer.Start()
    [void]$window.ShowDialog()
}

# ============================================================================
# 5. 全功能终端交互模式 (-Mode CLI v8.0)
# ============================================================================
function Start-UltimateCli {
    $Host.UI.RawUI.WindowTitle = "🛡️ AI Agent 哨兵舱 v8.0 (CLI 终极模式)"
    $resolvedPath = (Resolve-Path $WorkspacePath -ErrorAction SilentlyContinue).Path
    if (-not $resolvedPath) { $resolvedPath = $PWD.Path }

    Write-Host "========================================================================================" -ForegroundColor Cyan
    Write-Host " 🛡️ AI Agent 全栈行为感知与安全哨兵舱 (Agent Sentinel) v8.0 (CLI 终端模式)" -ForegroundColor Cyan
    Write-Host "    正在建立工作区双轨微快照: $resolvedPath ..." -ForegroundColor Gray
    $baselineCount = Initialize-WorkspaceSnapshot -RootPath $resolvedPath
    Write-Host "    ✅ 已备份 $baselineCount 个核心文件基线 | 快捷键说明：" -ForegroundColor Green
    Write-Host "    [F] 冻结进程树  [R] 恢复进程树  [K] 强杀进程树  [U] 回退修改文件  [O] 清理孤儿进程  [Q] 退出" -ForegroundColor Yellow
    Write-Host "========================================================================================`n" -ForegroundColor Cyan

    $WatcherCtx = Start-WorkspaceFileWatcher -RootPath $resolvedPath
    $ActivePids = @{}
    $AgentFailures = @{}
    $LatestPid = [uint32]0
    $LatestModifiedFile = $null
    $LastEventRecordId = [long]0
    $Tick = 0

    try {
        $latestEvt = Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -FilterXPath "*[System[(EventID=4104)]]" -MaxEvents 1 -ErrorAction Stop
        if ($latestEvt) { $LastEventRecordId = [long]$latestEvt.RecordId }
    } catch {}

    foreach ($p in [System.Diagnostics.Process]::GetProcesses()) {
        $ActivePids[[uint32]$p.Id] = @{ PreExisting = $true; Handle = [IntPtr]::Zero }
    }

    try {
        while ($true) {
            $Tick++
            $now = Get-Date

            if ([Console]::KeyAvailable) {
                $key = [Console]::ReadKey($true).Key
                switch ($key) {
                    'F' {
                        if ($LatestPid -gt 0 -and (Suspend-ProcessTree -RootPid $LatestPid)) {
                            Write-Host "⏸️ [手动冻结] 已递归挂起后台进程树 PID: $LatestPid" -ForegroundColor Yellow
                        }
                    }
                    'R' {
                        if ($LatestPid -gt 0 -and (Resume-ProcessTree -RootPid $LatestPid)) {
                            Write-Host "▶️ [手动恢复] 已递归恢复后台进程树 PID: $LatestPid" -ForegroundColor Green
                        }
                    }
                    'K' {
                        if ($LatestPid -gt 0 -and (Stop-ProcessTree -TargetPid $LatestPid)) {
                            Write-Host "🛑 [强杀进程树] 已终止进程树 PID: $LatestPid" -ForegroundColor Red
                        }
                    }
                    'U' {
                        if ($null -ne $LatestModifiedFile -and $LatestModifiedFile.SnapPath -and (Test-Path $LatestModifiedFile.SnapPath)) {
                            $WatcherCtx.SuppressUntil = [DateTime]::UtcNow.AddMilliseconds(800)
                            Copy-Item -Path $LatestModifiedFile.SnapPath -Destination $LatestModifiedFile.FullPath -Force
                            Write-Host "⏪ [一键后悔药] 已成功将文件回退至上一正常快照: $($LatestModifiedFile.RelPath)" -ForegroundColor Magenta
                        } else {
                            Write-Host "ℹ️ 当前没有可回退的已修改文件。" -ForegroundColor Gray
                        }
                    }
                    'O' {
                        $orphans = Find-OrphanProcesses
                        $killed = 0
                        foreach ($o in $orphans) {
                            if (Stop-ProcessTree -TargetPid $o.Pid) { $killed++ }
                        }
                        $gitLock = Join-Path $resolvedPath ".git\index.lock"
                        if (Test-Path $gitLock) { Remove-Item $gitLock -Force -ErrorAction SilentlyContinue }
                        Write-Host "🧹 [孤儿与死锁清理] 已发现并清理 $killed 个后台孤儿进程，并检查释放 .git/index.lock。" -ForegroundColor Cyan
                    }
                    'Q' { break }
                }
            }

            $fastProcs = [System.Diagnostics.Process]::GetProcesses()
            $currentWatched = @{}
            $newCandidates = New-Object System.Collections.Generic.List[uint32]

            foreach ($fp in $fastProcs) {
                $fPid = [uint32]$fp.Id
                if ($fPid -eq $PID) { continue }
                if (-not $Script:WatchedProcessNames.ContainsKey($fp.ProcessName.ToLower())) { continue }
                $currentWatched[$fPid] = $true
                if (-not $ActivePids.ContainsKey($fPid)) { $newCandidates.Add($fPid) }
            }

            if ($newCandidates.Count -gt 0) {
                $cimMap = Query-CimProcessesByPids -PidList $newCandidates
                foreach ($newPid in $newCandidates) {
                    if (-not $cimMap.ContainsKey($newPid)) {
                        $ActivePids[$newPid] = @{ PreExisting = $true; Handle = [IntPtr]::Zero }
                        continue
                    }
                    $proc = $cimMap[$newPid]
                    $ancInfo = Get-ProcessAncestryAndAgent -StartParentPid ([uint32]$proc.ParentProcessId)
                    $ancestry = $ancInfo.ChainString
                    $agentInst = $ancInfo.AgentInstance
                    $cmdLine = if ($proc.CommandLine) { $proc.CommandLine.Trim() } else { "(无参数)" }

                    if ($FilterAgent -and ("$agentInst $ancestry $($proc.Name) $cmdLine" -notmatch $FilterAgent)) {
                        $ActivePids[$newPid] = @{ PreExisting = $true; Handle = [IntPtr]::Zero }
                        continue
                    }

                    if (-not $AgentFailures.ContainsKey($agentInst)) { $AgentFailures[$agentInst] = 0 }

                    $liveCwd = Resolve-ProcessCwdSmart -TargetPid $newPid -CmdLine $cmdLine -DefaultWorkspace $resolvedPath
                    $hProc = [SentinelNativeApiV8]::OpenProcess([SentinelNativeApiV8]::PROCESS_QUERY_LIMITED_INFORMATION, $false, $newPid)
                    $decoded = Decode-AgentCommand -CmdLine $cmdLine
                    $risk = Evaluate-CommandRisk -CmdLine $cmdLine -DecodedText $decoded
                    $netInfo = [SentinelNativeApiV8]::GetFastTcpSummary($newPid)
                    $LatestPid = $newPid

                    $color = switch ($risk.Score) { 3 { "Red" } 2 { "Yellow" } default { "Green" } }
                    Write-Host "[$($now.ToString('HH:mm:ss.fff'))] [$agentInst] $($risk.Badge) 捕获: $($proc.Name) (PID: $newPid) $(if($netInfo){"[$netInfo]"})" -ForegroundColor $color
                    Write-Host "  ├─ 调用族谱: $ancestry" -ForegroundColor Gray
                    if ($liveCwd) { Write-Host "  ├─ 工作目录: $liveCwd" -ForegroundColor DarkCyan }
                    Write-Host "  └─ 命令行  : $cmdLine" -ForegroundColor Cyan
                    if ($decoded) { Write-Host "  🔓 解码明文: $decoded" -ForegroundColor Magenta }

                    if (($risk.Score -ge 3 -or $AgentFailures[$agentInst] -ge $MaxConsecutiveFailures) -and $AutoFreezeHighRisk) {
                        if (Suspend-ProcessTree -RootPid $newPid) {
                            Write-Host "  ⏸️ [自动防御] 已递归冻结 [$agentInst] 的进程树！按 [R] 恢复放行，或按 [K] 终止进程树。" -ForegroundColor Red
                        }
                    }

                    $ActivePids[$newPid] = @{ PreExisting = $false; StartTime = $now; Handle = $hProc; AgentInstance = $agentInst }
                }
            }

            $exited = @($ActivePids.Keys | Where-Object { -not $currentWatched.ContainsKey($_) })
            foreach ($oldPid in $exited) {
                $entry = $ActivePids[$oldPid]
                $ActivePids.Remove($oldPid)
                if ($entry.Handle -and $entry.Handle -ne [IntPtr]::Zero) {
                    $exitCode = [SentinelNativeApiV8]::TryGetExitCode($entry.Handle)
                    [void][SentinelNativeApiV8]::CloseHandle($entry.Handle)
                } else { $exitCode = $null }

                if (-not $entry.PreExisting) {
                    $dur = [math]::Round(($now - $entry.StartTime).TotalSeconds, 2)
                    $agKey = $entry.AgentInstance
                    if ($null -ne $exitCode -and $exitCode -ne 0) {
                        $AgentFailures[$agKey] = [int]$AgentFailures[$agKey] + 1
                        Write-Host "[$($now.ToString('HH:mm:ss.fff'))] ❌ [$agKey] 进程报错退出 (PID: $oldPid) | 耗时: ${dur}s | ExitCode: $exitCode (该Agent连败: $($AgentFailures[$agKey]))" -ForegroundColor Red
                    } else {
                        if ($exitCode -eq 0) { $AgentFailures[$agKey] = 0 }
                        Write-Host "[$($now.ToString('HH:mm:ss.fff'))] ✅ [$agKey] 进程结束 (PID: $oldPid) | 耗时: ${dur}s | ExitCode: $exitCode" -ForegroundColor DarkGray
                    }
                }
            }

            $fEvt = $null
            while ($WatcherCtx.Queue.TryDequeue([ref]$fEvt)) {
                $rel = Get-RelativeWorkspacePath -BasePath $resolvedPath -FullPath $fEvt.FullPath
                $baseBackup = Join-Path $Script:BackupRoot ("Baseline\" + $rel)
                $workCopy   = Join-Path $Script:BackupRoot ("WorkingCopy\" + $rel)
                $prevSnap   = Join-Path $Script:BackupRoot ("PrevVersion\" + $rel)

                if (Test-Path $workCopy) {
                    $prevDir = Split-Path $prevSnap -Parent
                    if (-not (Test-Path $prevDir)) { New-Item -ItemType Directory -Path $prevDir -Force | Out-Null }
                    Copy-Item -Path $workCopy -Destination $prevSnap -Force -ErrorAction SilentlyContinue
                }
                if ((Test-Path $fEvt.FullPath -PathType Leaf) -and ((Get-Item $fEvt.FullPath).Length -lt 2MB)) {
                    $workDir = Split-Path $workCopy -Parent
                    if (-not (Test-Path $workDir)) { New-Item -ItemType Directory -Path $workDir -Force | Out-Null }
                    Copy-Item -Path $fEvt.FullPath -Destination $workCopy -Force -ErrorAction SilentlyContinue
                }

                $snapToUse = if (Test-Path $prevSnap) { $prevSnap } elseif (Test-Path $baseBackup) { $baseBackup } else { $null }
                if ($snapToUse) {
                    $LatestModifiedFile = @{ RelPath = $rel; FullPath = $fEvt.FullPath; SnapPath = $snapToUse }
                }
                Write-Host "[$($fEvt.TimeStr)] 📝 [文件哨兵 - $($fEvt.ChangeType)] $rel $(if($snapToUse){'(按 [U] 可回退版本)'})" -ForegroundColor DarkYellow
            }

            if (($Tick % 10) -eq 0) {
                try {
                    $xpath = "*[System[(EventID=4104) and (EventRecordID > $LastEventRecordId)]]"
                    $evts = Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -FilterXPath $xpath -MaxEvents 10 -ErrorAction Stop | Sort-Object RecordId
                    foreach ($ev in $evts) {
                        $LastEventRecordId = [long]$ev.RecordId
                        if ($ev.ProcessId -eq $PID) { continue }
                        $scriptText = if ($ev.Properties.Count -ge 3) { [string]$ev.Properties[2].Value } else { $ev.Message }
                        if ([string]::IsNullOrWhiteSpace($scriptText) -or $scriptText -match '^\s*(prompt|Out-Default)\s*$') { continue }
                        $short = ($scriptText -replace "\r?\n", " ").Trim()
                        if ($short.Length -gt 120) { $short = $short.Substring(0, 120) + "..." }
                        Write-Host "[$($ev.TimeCreated.ToString('HH:mm:ss.fff'))] 🧠 [4104 内存脚本块 PID:$($ev.ProcessId)] $short" -ForegroundColor Magenta
                    }
                } catch {}
            }

            Start-Sleep -Milliseconds $PollIntervalMs
        }
    } finally {
        Stop-WorkspaceFileWatcher -SyncContext $WatcherCtx
        foreach ($v in $ActivePids.Values) {
            if ($v.Handle -and $v.Handle -ne [IntPtr]::Zero) {
                [void][SentinelNativeApiV8]::CloseHandle($v.Handle)
            }
        }
    }
}

if ($Mode -eq "CLI") {
    Start-UltimateCli
} else {
    Start-UltimateGui
}
