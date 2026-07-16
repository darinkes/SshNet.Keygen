using System;
using NUnit.Framework;
using Renci.SshNet;
using SshNet.Keygen.Extensions;
using SshNet.Keygen.SshKeyEncryption;

namespace SshNet.Keygen.Tests
{
    // Round-trips every generated key format back through SSH.NET's own parser.
    // SSH.NET could not read PuTTY keys until after 2024.2.0 (the library's range
    // floor), so those cases run only when a new enough SSH.NET is resolved - the
    // -p:SshNetVersion CI leg. OpenSSH round-trips on every supported version.
    public class SshNetReadTests
    {
        private static readonly Version LoadedSshNet =
            typeof(PrivateKeyFile).Assembly.GetName().Version ?? new Version();
        private static readonly Version PuttyReadable = new(2025, 1, 0);

        [Test]
        public void SshNetReadsGeneratedKey(
            [Values(SshKeyType.ED25519, SshKeyType.RSA, SshKeyType.ECDSA)] SshKeyType keyType,
            [Values(SshKeyFormat.OpenSSH, SshKeyFormat.PuTTYv2, SshKeyFormat.PuTTYv3)] SshKeyFormat format,
            [Values(false, true)] bool encrypted)
        {
            var isPutty = format is SshKeyFormat.PuTTYv2 or SshKeyFormat.PuTTYv3;
            if (isPutty && LoadedSshNet < PuttyReadable)
                Assert.Ignore($"SSH.NET {LoadedSshNet} cannot read PuTTY keys; needs >= {PuttyReadable}");

            const string password = "12345";
            var info = new SshKeyGenerateInfo(keyType)
            {
                KeyFormat = format,
                Encryption = encrypted ? new SshKeyEncryptionAes256(password) : new SshKeyEncryptionNone()
            };

            var key = SshKey.Generate(info);
            var exported = format == SshKeyFormat.OpenSSH
                ? key.ToOpenSshFormat(info.Encryption)
                : key.ToPuttyFormat(info.Encryption, format);

            Assert.DoesNotThrow((Action)(() =>
                _ = new PrivateKeyFile(exported.ToStream(), encrypted ? password : null)));
        }
    }
}
