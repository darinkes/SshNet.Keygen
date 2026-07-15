using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using NUnit.Framework;
using SshNet.Keygen.Extensions;
using SshNet.Keygen.SshKeyEncryption;

namespace SshNet.Keygen.Tests
{
    // Verifies generated keys are accepted by the real OpenSSH ssh-keygen and PuTTY
    // puttygen tools, not just re-read by SSH.NET. Skipped unless
    // SSHNET_KEYGEN_INTEROP_REQUIRED is set (the Ubuntu CI job sets it and installs
    // the tools), so a normal local `dotnet test` never shells out.
    public class InteropTests
    {
        private const string Passphrase = "SshNetKeygenInterop1";

        [Test]
        public void SshKeygenAcceptsGeneratedKey(
            [Values(SshKeyType.ED25519, SshKeyType.RSA, SshKeyType.ECDSA)] SshKeyType keyType,
            [Values(false, true)] bool encrypted)
        {
            RequireTool("ssh-keygen");

            using var dir = new TempDir();
            var keyPath = Path.Combine(dir.Path, "id");
            var key = Generate(keyType, SshKeyFormat.OpenSSH, encrypted, keyPath);

            // ssh-keygen -y derives the public key from the private key, decrypting first
            var result = Run("ssh-keygen", $"-y -P \"{(encrypted ? Passphrase : "")}\" -f \"{keyPath}\"");
            Assert.That(result.Code, Is.Zero, result.Stderr);
            Assert.That(PublicKeyId(result.Stdout), Is.EqualTo(PublicKeyId(key.ToOpenSshPublicFormat())));
        }

        [Test]
        public void PuttygenAcceptsGeneratedKey(
            [Values(SshKeyType.ED25519, SshKeyType.RSA, SshKeyType.ECDSA)] SshKeyType keyType,
            [Values(SshKeyFormat.PuTTYv2, SshKeyFormat.PuTTYv3)] SshKeyFormat format,
            [Values(false, true)] bool encrypted)
        {
            // the Windows puttygen is GUI-only; the CLI puttygen ships with putty-tools on Linux
            RequireTool("puttygen", skipOnWindows: true);

            using var dir = new TempDir();
            var ppkPath = Path.Combine(dir.Path, "id.ppk");
            var outPath = Path.Combine(dir.Path, "id.pub");
            var key = Generate(keyType, format, encrypted, ppkPath);

            var args = $"\"{ppkPath}\" -O public-openssh -o \"{outPath}\"";
            if (encrypted)
            {
                var passFile = Path.Combine(dir.Path, "pass");
                File.WriteAllText(passFile, Passphrase + "\n");
                args += $" --old-passphrase \"{passFile}\"";
            }

            var result = Run("puttygen", args);
            Assert.That(result.Code, Is.Zero, result.Stderr);
            Assert.That(PublicKeyId(File.ReadAllText(outPath)), Is.EqualTo(PublicKeyId(key.ToOpenSshPublicFormat())));
        }

        private static GeneratedPrivateKey Generate(SshKeyType keyType, SshKeyFormat format, bool encrypted, string path)
        {
            var info = new SshKeyGenerateInfo(keyType)
            {
                KeyFormat = format,
                Encryption = encrypted ? new SshKeyEncryptionAes256(Passphrase) : new SshKeyEncryptionNone()
            };
            return SshKey.Generate(path, FileMode.Create, info);
        }

        // "<type> <base64>" — the identifying fields of an OpenSSH public key line, ignoring the comment
        private static string PublicKeyId(string openSshPublicKey)
        {
            var parts = openSshPublicKey.Split(new[] { ' ', '\t', '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
            Assert.That(parts.Length, Is.GreaterThanOrEqualTo(2), $"unexpected public key: {openSshPublicKey}");
            return $"{parts[0]} {parts[1]}";
        }

        private static void RequireTool(string exe, bool skipOnWindows = false)
        {
            if (Environment.GetEnvironmentVariable("SSHNET_KEYGEN_INTEROP_REQUIRED") is not { Length: > 0 })
                Assert.Ignore("set SSHNET_KEYGEN_INTEROP_REQUIRED to run external-tool interop tests");
            if (skipOnWindows && RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                Assert.Ignore($"{exe} interop runs on non-Windows only");
            if (!OnPath(exe))
                Assert.Fail($"{exe} not found on PATH");
        }

        private static bool OnPath(string exe)
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

        private static (int Code, string Stdout, string Stderr) Run(string exe, string args)
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
            var stdout = process.StandardOutput.ReadToEndAsync();
            var stderr = process.StandardError.ReadToEndAsync();
            if (!process.WaitForExit(30000))
            {
                try { process.Kill(); } catch { /* already gone */ }
                Assert.Fail($"{exe} did not exit within 30s");
            }
            return (process.ExitCode, stdout.GetAwaiter().GetResult(), stderr.GetAwaiter().GetResult());
        }

        private sealed class TempDir : IDisposable
        {
            public string Path { get; }

            public TempDir()
            {
                Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "sshnet-keygen-interop", Guid.NewGuid().ToString("N"));
                Directory.CreateDirectory(Path);
            }

            public void Dispose()
            {
                try { Directory.Delete(Path, true); } catch { /* best effort */ }
            }
        }
    }
}
