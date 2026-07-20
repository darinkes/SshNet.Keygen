using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;

namespace SshNet.Keygen.Tests
{
    // Minimal helper to shell out to OpenSSH tools (ssh-keygen) for real-world verification.
    // Unlike InteropTests this is not env-gated: callers skip gracefully when the tool is absent.
    internal static class ExternalTool
    {
        public static bool OnPath(string exe)
        {
            var names = RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
                ? new[] { exe + ".exe", exe + ".com", exe }
                : new[] { exe };
            return (Environment.GetEnvironmentVariable("PATH") ?? "")
                .Split(Path.PathSeparator)
                .Where(d => !string.IsNullOrEmpty(d))
                .Any(d => names.Any(n => SafeExists(Path.Combine(d, n))));
        }

        private static bool SafeExists(string path)
        {
            try { return File.Exists(path); }
            catch { return false; }
        }

        public static (int Code, string Stdout, string Stderr) Run(string exe, string args)
        {
            var psi = new ProcessStartInfo
            {
                FileName = exe,
                Arguments = args,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var process = Process.Start(psi);
            var stdout = process!.StandardOutput.ReadToEndAsync();
            var stderr = process.StandardError.ReadToEndAsync();
            if (!process.WaitForExit(30000))
            {
                try { process.Kill(); } catch { /* already gone */ }
                throw new TimeoutException($"{exe} did not exit within 30s");
            }
            return (process.ExitCode, stdout.GetAwaiter().GetResult(), stderr.GetAwaiter().GetResult());
        }

        public static void RestrictToOwner(string path)
        {
#if NET8_0_OR_GREATER
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
#endif
        }

        public sealed class TempDir : IDisposable
        {
            public string Path { get; }

            public TempDir()
            {
                Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "sshnet-keygen-tests", Guid.NewGuid().ToString("N"));
                Directory.CreateDirectory(Path);
            }

            public void Dispose()
            {
                try { Directory.Delete(Path, true); } catch { /* best effort */ }
            }
        }
    }
}
