using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace AgentSentinel
{
    static class Program
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool AttachConsole(int dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr GetStdHandle(int nStdHandle);

        private const int ATTACH_PARENT_PROCESS = -1;
        private const int STD_OUTPUT_HANDLE = -11;
        private const int STD_ERROR_HANDLE = -12;

        private static void EnsureConsoleOutput()
        {
            AttachConsole(ATTACH_PARENT_PROCESS);
            IntPtr stdOut = GetStdHandle(STD_OUTPUT_HANDLE);
            if (stdOut != IntPtr.Zero && stdOut != new IntPtr(-1))
            {
                SafeFileHandle safeOut = new SafeFileHandle(stdOut, false);
                FileStream fsOut = new FileStream(safeOut, FileAccess.Write);
                StreamWriter swOut = new StreamWriter(fsOut, Encoding.UTF8) { AutoFlush = true };
                Console.SetOut(swOut);
            }

            IntPtr stdErr = GetStdHandle(STD_ERROR_HANDLE);
            if (stdErr != IntPtr.Zero && stdErr != new IntPtr(-1))
            {
                SafeFileHandle safeErr = new SafeFileHandle(stdErr, false);
                FileStream fsErr = new FileStream(safeErr, FileAccess.Write);
                StreamWriter swErr = new StreamWriter(fsErr, Encoding.UTF8) { AutoFlush = true };
                Console.SetError(swErr);
            }
        }

        [STAThread]
        static int Main(string[] args)
        {
            bool isCliExplicit = false;
            bool isHelpOrVersion = false;
            bool isExtract = false;
            string extractPath = null;

            for (int i = 0; i < args.Length; i++)
            {
                string a = args[i].Trim().ToLowerInvariant();
                if (a == "-h" || a == "--help" || a == "/?" || a == "-help")
                {
                    isHelpOrVersion = true;
                    break;
                }
                if (a == "-v" || a == "--version" || a == "-version")
                {
                    isHelpOrVersion = true;
                    break;
                }
                if (a == "--extract" || a == "-extract")
                {
                    isExtract = true;
                    if (i + 1 < args.Length && !args[i + 1].StartsWith("-"))
                    {
                        extractPath = args[i + 1];
                    }
                    break;
                }
                if ((a == "-mode" || a == "/mode") && i + 1 < args.Length)
                {
                    if (args[i + 1].Equals("CLI", StringComparison.OrdinalIgnoreCase))
                    {
                        isCliExplicit = true;
                    }
                }
                if (a == "--cli" || a == "-cli")
                {
                    isCliExplicit = true;
                }
            }

            if (isHelpOrVersion)
            {
                EnsureConsoleOutput();
                PrintBannerAndHelp();
                return 0;
            }

            if (isExtract)
            {
                EnsureConsoleOutput();
                string outPath = string.IsNullOrEmpty(extractPath) ? "agent_sentinel_windows.ps1" : extractPath;
                try
                {
                    ExtractEmbeddedScriptToFile(outPath);
                    Console.WriteLine("[+] 成功提取嵌入脚本至: " + Path.GetFullPath(outPath));
                    return 0;
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine("[-] 提取失败: " + ex.Message);
                    return 1;
                }
            }

            try
            {
                // 1. 同步解压核心脚本至持久化目录
                string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
                string sentinelDir = Path.Combine(localAppData, "AgentSentinel");
                if (!Directory.Exists(sentinelDir))
                {
                    Directory.CreateDirectory(sentinelDir);
                }

                string scriptPath = Path.Combine(sentinelDir, "agent_sentinel_windows.ps1");
                SyncEmbeddedScript(scriptPath);

                // 2. 构造 PowerShell 启动命令
                StringBuilder sb = new StringBuilder();
                sb.Append("-NoProfile -STA -ExecutionPolicy Bypass -File \"");
                sb.Append(scriptPath);
                sb.Append("\"");

                for (int i = 0; i < args.Length; i++)
                {
                    string rawArg = args[i];
                    sb.Append(" ");
                    if (rawArg.Contains(" ") || rawArg.Contains("\""))
                    {
                        sb.Append("\"").Append(rawArg.Replace("\"", "\\\"")).Append("\"");
                    }
                    else
                    {
                        sb.Append(rawArg);
                    }
                }

                ProcessStartInfo psi = new ProcessStartInfo();
                psi.FileName = "powershell.exe";
                psi.Arguments = sb.ToString();
                psi.UseShellExecute = false;
                psi.CreateNoWindow = false;

                using (Process proc = Process.Start(psi))
                {
                    if (proc == null)
                    {
                        EnsureConsoleOutput();
                        Console.Error.WriteLine("[-] 无法启动 powershell.exe 运行时进程。");
                        return 1;
                    }

                    proc.WaitForExit();
                    return proc.ExitCode;
                }
            }
            catch (Exception ex)
            {
                EnsureConsoleOutput();
                Console.Error.WriteLine("[-] 防御舱运行时异常: " + ex.Message);
                return 1;
            }
        }

        private static byte[] GetEmbeddedScriptBytes()
        {
            Assembly asm = Assembly.GetExecutingAssembly();
            using (Stream stream = asm.GetManifestResourceStream("AgentSentinel.script.ps1"))
            {
                if (stream == null)
                {
                    throw new InvalidOperationException("未找到嵌入的核心脚本资源 AgentSentinel.script.ps1");
                }
                byte[] data = new byte[stream.Length];
                stream.Read(data, 0, data.Length);
                return data;
            }
        }

        private static void ExtractEmbeddedScriptToFile(string destPath)
        {
            byte[] bytes = GetEmbeddedScriptBytes();
            string dir = Path.GetDirectoryName(Path.GetFullPath(destPath));
            if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
            {
                Directory.CreateDirectory(dir);
            }
            File.WriteAllBytes(destPath, bytes);
        }

        private static void SyncEmbeddedScript(string targetPath)
        {
            byte[] embeddedBytes = GetEmbeddedScriptBytes();
            if (File.Exists(targetPath))
            {
                try
                {
                    byte[] existingBytes = File.ReadAllBytes(targetPath);
                    if (ComputeSha256(existingBytes) == ComputeSha256(embeddedBytes))
                    {
                        return; // 哈希一致，无需重新写入
                    }
                }
                catch { }
            }
            File.WriteAllBytes(targetPath, embeddedBytes);
        }

        private static string ComputeSha256(byte[] data)
        {
            using (SHA256 sha = SHA256.Create())
            {
                byte[] hash = sha.ComputeHash(data);
                StringBuilder sb = new StringBuilder(hash.Length * 2);
                foreach (byte b in hash)
                {
                    sb.Append(b.ToString("x2"));
                }
                return sb.ToString();
            }
        }

        private static void PrintBannerAndHelp()
        {
            Console.WriteLine(@"================================================================================");
            Console.WriteLine(@"  AI Agent 全栈行为感知与安全哨兵舱 (Agent Sentinel) (Windows 独立可执行版 v8.0)");
            Console.WriteLine(@"================================================================================");
            Console.WriteLine(@"用法: agent_sentinel_windows.exe [参数选项]");
            Console.WriteLine();
            Console.WriteLine(@"核心选项:");
            Console.WriteLine(@"  -WorkspacePath <路径>       需要保护和监控文件变更的项目工作区路径（默认当前目录）");
            Console.WriteLine(@"  -Mode <Auto|GUI|CLI>        运行模式：Auto (默认，有桌面启动 WPF，否则 CLI)、GUI 或 CLI");
            Console.WriteLine(@"  -PollIntervalMs <毫秒>      极速采样间隔（毫秒），默认 120ms");
            Console.WriteLine(@"  -FilterAgent <关键字>       可选：初始过滤关键字（如 cursor|claude）");
            Console.WriteLine(@"  -ExtraWatchNames <名称>     可选：额外追加监控的进程名（逗号分隔）");
            Console.WriteLine(@"  -AutoFreezeHighRisk <bool>  捕获高危命令或死循环时是否自动冻结进程树（默认 $true）");
            Console.WriteLine(@"  -MaxConsecutiveFailures <n> 单个 Agent 实例的连续报错熔断阈值（默认 5 次）");
            Console.WriteLine();
            Console.WriteLine(@"实用选项:");
            Console.WriteLine(@"  --extract [目标路径]        提取内置的 PowerShell 源码脚本 (.ps1)");
            Console.WriteLine(@"  -v, --version               查看版本号");
            Console.WriteLine(@"  -h, --help, /?              显示此帮助信息");
            Console.WriteLine(@"================================================================================");
        }
    }
}
