using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using NUnit.Framework;
using NUnit.Framework.Legacy;
using Renci.SshNet;
using Renci.SshNet.Security;
using Renci.SshNet.Security.Cryptography;

namespace SshNet.Keygen.Tests
{
    // Mints signed OpenSSH certificates. The signature is verified two ways: self-contained via
    // SSH.NET (always on) and, when available, by the real ssh-keygen -L (the ground truth).
    public class CertificateTests
    {
        private static GeneratedPrivateKey Gen(SshKeyType type)
        {
            return SshKey.Generate(new SshKeyGenerateInfo(type));
        }

        private static Key KeyOf(IPrivateKeySource src)
        {
            return ((KeyHostAlgorithm)src.HostKeyAlgorithms.First()).Key;
        }

        [Test]
        public void SignsAndSelfVerifies(
            [Values(SshKeyType.RSA, SshKeyType.ECDSA, SshKeyType.ED25519)] SshKeyType certifiedType,
            [Values(SshKeyType.RSA, SshKeyType.ECDSA, SshKeyType.ED25519)] SshKeyType caType)
        {
            var certified = Gen(certifiedType);
            var ca = Gen(caType);

            var cert = new SshCertificateBuilder(certified)
                .WithSerial(4711)
                .WithType(SshCertificateType.User)
                .WithKeyId("self-verify")
                .WithPrincipal("alice")
                .WithPrincipal("bob")
                .SignWith(ca);

            var (signed, signature) = SplitSignature(cert.ToByteArray(), KeyOf(certified).ToString()!);

            // the CA signature validates over everything preceding it
            Assert.That(CaHostAlgorithm(KeyOf(ca)).VerifySignature(signed, signature), Is.True);

            // and the leading fields round-trip
            var r = new Reader(cert.ToByteArray());
            ClassicAssert.AreEqual($"{KeyOf(certified)}-cert-v01@openssh.com", r.String());
            r.String();                                   // nonce
            foreach (var _ in PubFields(KeyOf(certified).ToString()!)) r.String();
            ClassicAssert.AreEqual(4711UL, r.UInt64());   // serial
            ClassicAssert.AreEqual(1U, r.UInt32());       // user cert
            ClassicAssert.AreEqual("self-verify", r.String());
        }

        [Test]
        public void NonAsciiKeyIdAndPrincipalAreUtf8()
        {
            // regression: ASCII encoding minted certificates with principal "m?ller"
            var cert = new SshCertificateBuilder(Gen(SshKeyType.ED25519))
                .WithKeyId("müller-id")
                .WithPrincipal("müller")
                .SignWith(Gen(SshKeyType.ED25519));

            var r = new Reader(cert.ToByteArray());
            r.String();                                   // type
            r.String();                                   // nonce
            r.String();                                   // ed25519 pk
            r.UInt64();                                   // serial
            r.UInt32();                                   // cert type
            ClassicAssert.AreEqual(Encoding.UTF8.GetBytes("müller-id"), r.String());
            var principals = new Reader(r.String());
            ClassicAssert.AreEqual(Encoding.UTF8.GetBytes("müller"), principals.String());
        }

        [Test]
        public void RejectsEmptyNonce()
        {
            var builder = new SshCertificateBuilder(Gen(SshKeyType.ED25519));
            Assert.Throws<ArgumentException>((Action)(() => builder.WithNonce(null!)));
            Assert.Throws<ArgumentException>((Action)(() => builder.WithNonce(Array.Empty<byte>())));
        }

        [Test]
        public void RejectsInvertedValidity()
        {
            var builder = new SshCertificateBuilder(Gen(SshKeyType.ED25519));
            Assert.Throws<ArgumentException>((Action)(() => builder.WithValidity(
                new DateTime(2031, 1, 1, 0, 0, 0, DateTimeKind.Utc),
                new DateTime(2030, 1, 1, 0, 0, 0, DateTimeKind.Utc))));
        }

        [Test]
        public void SshKeygenAcceptsCertificate(
            [Values(SshKeyType.RSA, SshKeyType.ECDSA, SshKeyType.ED25519)] SshKeyType certifiedType,
            [Values(SshKeyType.RSA, SshKeyType.ECDSA, SshKeyType.ED25519)] SshKeyType caType)
        {
            if (!OnPath("ssh-keygen"))
                Assert.Ignore("ssh-keygen not on PATH");

            var certified = Gen(certifiedType);
            var ca = Gen(caType);

            var cert = new SshCertificateBuilder(certified)
                .WithSerial(123456789)
                .WithType(SshCertificateType.User)
                .WithKeyId("interop-key-id")
                .WithPrincipals(new[] { "alice", "bob" })
                .SignWith(ca);

            var dir = Path.Combine(Path.GetTempPath(), "sshnet-keygen-cert", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(dir);
            try
            {
                var file = Path.Combine(dir, "id-cert.pub");
                File.WriteAllText(file, cert.ToOpenSshPublicFormat());

                var result = Run("ssh-keygen", $"-L -f \"{file}\"");
                Assert.That(result.Code, Is.Zero, result.Stderr + result.Stdout);

                StringAssert.Contains("user certificate", result.Stdout);
                StringAssert.Contains("Serial: 123456789", result.Stdout);
                StringAssert.Contains("Key ID: \"interop-key-id\"", result.Stdout);
                StringAssert.Contains("Signing CA", result.Stdout);
                StringAssert.Contains("alice", result.Stdout);
                StringAssert.Contains("bob", result.Stdout);
                // default user extensions are present
                StringAssert.Contains("permit-pty", result.Stdout);
            }
            finally
            {
                try { Directory.Delete(dir, true); } catch { /* best effort */ }
            }
        }

        [Test]
        public void HostCertificateWithValidityAndCriticalOption()
        {
            if (!OnPath("ssh-keygen"))
                Assert.Ignore("ssh-keygen not on PATH");

            var certified = Gen(SshKeyType.ED25519);
            var ca = Gen(SshKeyType.RSA);

            var cert = new SshCertificateBuilder(certified)
                .WithType(SshCertificateType.Host)
                .WithSerial(7)
                .WithKeyId("web01")
                .WithPrincipal("web01.example.com")
                .WithValidity(new DateTime(2030, 1, 1, 0, 0, 0, DateTimeKind.Utc),
                              new DateTime(2031, 1, 1, 0, 0, 0, DateTimeKind.Utc))
                .WithCriticalOption("force-command", "/usr/bin/true")
                .SignWith(ca);

            var dir = Path.Combine(Path.GetTempPath(), "sshnet-keygen-cert", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(dir);
            try
            {
                var file = Path.Combine(dir, "host-cert.pub");
                File.WriteAllText(file, cert.ToOpenSshPublicFormat());

                var result = Run("ssh-keygen", $"-L -f \"{file}\"");
                Assert.That(result.Code, Is.Zero, result.Stderr + result.Stdout);
                StringAssert.Contains("host certificate", result.Stdout);
                StringAssert.Contains("force-command", result.Stdout);
                StringAssert.Contains("web01.example.com", result.Stdout);
                // a host cert carries no default extensions
                StringAssert.Contains("Extensions: (none)", result.Stdout);
            }
            finally
            {
                try { Directory.Delete(dir, true); } catch { /* best effort */ }
            }
        }

        [Test]
        public void FingerprintMatchesSshKeygen(
            [Values(SshKeyType.RSA, SshKeyType.ECDSA, SshKeyType.ED25519)] SshKeyType certifiedType)
        {
            if (!OnPath("ssh-keygen"))
                Assert.Ignore("ssh-keygen not on PATH");

            var cert = new SshCertificateBuilder(Gen(certifiedType))
                .WithKeyId("fp").WithPrincipal("alice").SignWith(Gen(SshKeyType.ED25519));

            var dir = Path.Combine(Path.GetTempPath(), "sshnet-keygen-cert", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(dir);
            try
            {
                var file = Path.Combine(dir, "id-cert.pub");
                File.WriteAllText(file, cert.ToOpenSshPublicFormat());

                var result = Run("ssh-keygen", $"-l -f \"{file}\"");
                Assert.That(result.Code, Is.Zero, result.Stderr + result.Stdout);
                var fingerprint = result.Stdout.Split(' ').First(token => token.StartsWith("SHA256:"));
                ClassicAssert.AreEqual(fingerprint, cert.Fingerprint());
            }
            finally
            {
                try { Directory.Delete(dir, true); } catch { /* best effort */ }
            }
        }

        private static HostAlgorithm CaHostAlgorithm(Key caKey)
        {
            if (caKey is RsaKey rsaKey)
                return new KeyHostAlgorithm("rsa-sha2-512", caKey, new RsaDigitalSignature(rsaKey, System.Security.Cryptography.HashAlgorithmName.SHA512));
            return new KeyHostAlgorithm(caKey.ToString(), caKey);
        }

        private static IEnumerable<int> PubFields(string alg)
        {
            var count = alg == "ssh-ed25519" ? 1 : 2; // rsa: e,n / ecdsa: curve,Q / ed25519: pk
            return Enumerable.Range(0, count);
        }

        // (everything before the trailing signature string, the signature string content)
        private static (byte[] Signed, byte[] Signature) SplitSignature(byte[] blob, string certifiedAlg)
        {
            var r = new Reader(blob);
            r.String();                          // type
            r.String();                          // nonce
            foreach (var _ in PubFields(certifiedAlg)) r.String();
            r.UInt64();                          // serial
            r.UInt32();                          // type
            r.String();                          // key id
            r.String();                          // principals
            r.UInt64();                          // valid after
            r.UInt64();                          // valid before
            r.String();                          // critical options
            r.String();                          // extensions
            r.String();                          // reserved
            r.String();                          // signature key
            var signedLen = r.Position;
            var signature = r.String();
            var signed = new byte[signedLen];
            Buffer.BlockCopy(blob, 0, signed, 0, signedLen);
            return (signed, signature);
        }

        private sealed class Reader
        {
            private readonly byte[] _data;
            public int Position { get; private set; }

            public Reader(byte[] data) => _data = data;

            public uint UInt32()
            {
                var v = ((uint)_data[Position] << 24) | ((uint)_data[Position + 1] << 16) |
                        ((uint)_data[Position + 2] << 8) | _data[Position + 3];
                Position += 4;
                return v;
            }

            public ulong UInt64()
            {
                ulong v = 0;
                for (var i = 0; i < 8; i++)
                    v = (v << 8) | _data[Position + i];
                Position += 8;
                return v;
            }

            public byte[] String()
            {
                var len = (int)UInt32();
                var bytes = new byte[len];
                Buffer.BlockCopy(_data, Position, bytes, 0, len);
                Position += len;
                return bytes;
            }
        }

        #region ssh-keygen runner

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
            var stdout = process!.StandardOutput.ReadToEndAsync();
            var stderr = process.StandardError.ReadToEndAsync();
            if (!process.WaitForExit(30000))
            {
                try { process.Kill(); } catch { /* already gone */ }
                Assert.Fail($"{exe} did not exit within 30s");
            }
            return (process.ExitCode, stdout.GetAwaiter().GetResult(), stderr.GetAwaiter().GetResult());
        }

        #endregion
    }
}
