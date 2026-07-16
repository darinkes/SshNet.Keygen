using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
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
            RestrictToOwner(keyPath); // ssh-keygen refuses a world-readable private key

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

        [Test]
        public void SshKeygenVerifiesOurSignature(
            [Values(SshKeyType.ED25519, SshKeyType.RSA, SshKeyType.ECDSA)] SshKeyType keyType)
        {
            RequireTool("ssh-keygen");

            using var dir = new TempDir();
            var key = SshKey.Generate(new SshKeyGenerateInfo(keyType));
            var data = Encoding.UTF8.GetBytes("SshNet.Keygen real-world sign/verify");

            var sigPath = Path.Combine(dir.Path, "data.sig");
            File.WriteAllText(sigPath, key.Signature(data));

            // allowed_signers line: "<principal> <keytype> <base64> [comment]"
            const string identity = "signer@sshnet";
            var allowedSigners = Path.Combine(dir.Path, "allowed_signers");
            File.WriteAllText(allowedSigners, $"{identity} {key.ToOpenSshPublicFormat()}");

            // ssh-keygen -Y verify reads the signed data from stdin; our signatures use the "file" namespace
            var result = Run("ssh-keygen",
                $"-Y verify -f \"{allowedSigners}\" -I {identity} -n file -s \"{sigPath}\"", data);
            Assert.That(result.Code, Is.Zero, result.Stderr);
        }

        [Test]
        public void WeVerifySshKeygenSignature(
            [Values(SshKeyType.ED25519, SshKeyType.RSA, SshKeyType.ECDSA)] SshKeyType keyType)
        {
            RequireTool("ssh-keygen");

            using var dir = new TempDir();
            var keyPath = Path.Combine(dir.Path, "id");
            Generate(keyType, SshKeyFormat.OpenSSH, encrypted: false, keyPath);
            RestrictToOwner(keyPath); // ssh-keygen refuses a world-readable private key

            var data = Encoding.UTF8.GetBytes("SshNet.Keygen real-world sign/verify");
            var dataPath = Path.Combine(dir.Path, "data.txt");
            File.WriteAllBytes(dataPath, data);

            // ssh-keygen -Y sign writes the armored signature to <dataPath>.sig
            var sign = Run("ssh-keygen", $"-Y sign -f \"{keyPath}\" -n file \"{dataPath}\"");
            Assert.That(sign.Code, Is.Zero, sign.Stderr);

            var signature = File.ReadAllText(dataPath + ".sig");
            Assert.That(SshSignature.Verify(data, signature), Is.True);
        }

        [Test]
        public void SshKeygenHonoursOurSignatureNamespace()
        {
            RequireTool("ssh-keygen");

            using var dir = new TempDir();
            var key = SshKey.Generate(new SshKeyGenerateInfo(SshKeyType.ED25519));
            var data = Encoding.UTF8.GetBytes("SshNet.Keygen namespaced signature");

            var sigPath = Path.Combine(dir.Path, "data.sig");
            File.WriteAllText(sigPath, key.Signature(data, "git"));

            const string identity = "signer@sshnet";
            var allowedSigners = Path.Combine(dir.Path, "allowed_signers");
            File.WriteAllText(allowedSigners, $"{identity} {key.ToOpenSshPublicFormat()}");

            // ssh-keygen accepts the signature under the matching namespace...
            var match = Run("ssh-keygen",
                $"-Y verify -f \"{allowedSigners}\" -I {identity} -n git -s \"{sigPath}\"", data);
            Assert.That(match.Code, Is.Zero, match.Stderr);

            // ...and rejects it under a different one, proving the namespace is bound in
            var mismatch = Run("ssh-keygen",
                $"-Y verify -f \"{allowedSigners}\" -I {identity} -n file -s \"{sigPath}\"", data);
            Assert.That(mismatch.Code, Is.Not.Zero);
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

        private static void RestrictToOwner(string path)
        {
#if NET8_0_OR_GREATER
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
#endif
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

        private static (int Code, string Stdout, string Stderr) Run(string exe, string args, byte[] stdin = null)
        {
            var psi = new ProcessStartInfo
            {
                FileName = exe,
                Arguments = args,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                RedirectStandardInput = stdin != null,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var process = Process.Start(psi);
            if (stdin != null)
            {
                process.StandardInput.BaseStream.Write(stdin, 0, stdin.Length);
                process.StandardInput.Close();
            }
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
