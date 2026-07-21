using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using NUnit.Framework;
using NUnit.Framework.Legacy;
using Renci.SshNet;
using Renci.SshNet.Security;
using SshNet.Keygen.Extensions;

namespace SshNet.Keygen.Tests
{
    // Bridges BCL keys / PEM into SSH.NET keys and back. Correctness is proven three ways:
    // an SSH.NET round-trip, an RSA signature verified against the original BCL key, and
    // (when present) ssh-keygen parsing the exported public key.
    public class KeyInteropTests
    {
        // "<type> <base64>" of an OpenSSH public key line, ignoring the comment
        private static string PublicId(string openSshPublicKey)
        {
            var parts = openSshPublicKey.Split(new[] { ' ', '\t', '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
            Assert.That(parts.Length, Is.GreaterThanOrEqualTo(2), $"unexpected public key: {openSshPublicKey}");
            return $"{parts[0]} {parts[1]}";
        }

        // cryptographic part of the fingerprint (e.g. "SHA256:..."), ignoring the comment SSH.NET's reader drops
        private static string FpHash(IPrivateKeySource key)
        {
            return key.Fingerprint().Split(' ').First(t => t.Contains(':'));
        }

        private static void AssertRoundTrips(GeneratedPrivateKey gen)
        {
            var reloaded = new PrivateKeyFile(gen.ToOpenSshFormat().ToStream());
            ClassicAssert.AreEqual(FpHash(gen), FpHash(reloaded));
            ClassicAssert.AreEqual(PublicId(gen.ToOpenSshPublicFormat()), PublicId(reloaded.ToPublic()));
            SshKeygenParsesPublic(gen);
        }

        // "cross-check the exported public key parses" - skipped gracefully if ssh-keygen is absent
        private static void SshKeygenParsesPublic(GeneratedPrivateKey gen)
        {
            if (!ExternalTool.OnPath("ssh-keygen"))
                return;

            using var dir = new ExternalTool.TempDir();
            var pub = Path.Combine(dir.Path, "id.pub");
            File.WriteAllText(pub, gen.ToOpenSshPublicFormat());
            var r = ExternalTool.Run("ssh-keygen", $"-l -f \"{pub}\"");
            Assert.That(r.Code, Is.Zero, r.Stderr);
        }

        [Test]
        public void FromRsaKeyRoundTrips()
        {
            using var rsa = RSA.Create(2048);
            var gen = SshKey.FromKey(rsa, "rsa@interop");

            ClassicAssert.IsInstanceOf<RsaKey>(((KeyHostAlgorithm)gen.HostKeyAlgorithms.First()).Key);
            AssertRoundTrips(gen);

            // deterministic: same input imports to the same key, a different input to a different key
            ClassicAssert.AreEqual(FpHash(gen), FpHash(SshKey.FromKey(rsa)));
            using var other = RSA.Create(2048);
            ClassicAssert.AreNotEqual(FpHash(gen), FpHash(SshKey.FromKey(other)));
        }

        [Test]
        public void FromRsaKeyImportsPrivateKey()
        {
            // definitive: a signature made by the imported SSH key verifies against the original BCL key
            using var rsa = RSA.Create(2048);
            var gen = SshKey.FromKey(rsa);
            var data = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };

            var alg = gen.HostKeyAlgorithms.Cast<KeyHostAlgorithm>().First(h => h.Name == "rsa-sha2-256");
            var sig = SecondSshString(alg.Sign(data)); // blob = string alg, string signature

            ClassicAssert.IsTrue(rsa.VerifyData(data, sig, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
        }

        [Test]
        public void FromEcdsaKeyRoundTrips([Values(256, 384, 521)] int keySize)
        {
            using var ecdsa = ECDsa.Create(ECCurve.CreateFromFriendlyName($"nistp{keySize}"));
            var gen = SshKey.FromKey(ecdsa, "ecdsa@interop");

            ClassicAssert.IsInstanceOf<EcdsaKey>(((KeyHostAlgorithm)gen.HostKeyAlgorithms.First()).Key);
            ClassicAssert.AreEqual(keySize, ((KeyHostAlgorithm)gen.HostKeyAlgorithms.First()).Key.KeyLength);
            AssertRoundTrips(gen);
        }

        [Test]
        public void FromEcdsaRejectsNonNistCurve()
        {
            // regression: brainpool keys were mapped to a NIST curve by key size and failed deep inside SSH.NET
            ECDsa ecdsa;
            try
            {
                ecdsa = ECDsa.Create(ECCurve.CreateFromFriendlyName("brainpoolP256r1"));
                _ = ecdsa.ExportParameters(false);
            }
            catch (Exception)
            {
                Assert.Ignore("brainpoolP256r1 not supported on this platform");
                return;
            }

            using (ecdsa)
#if NET8_0_OR_GREATER
                Assert.Throws<NotSupportedException>((Action)(() => SshKey.FromKey(ecdsa)));
#else
                // net48 CNG hides the curve OID, so SSH.NET rejects the non-NIST point later
                Assert.Catch((Action)(() => SshKey.FromKey(ecdsa)));
#endif
        }

        [Test]
        public void FromEd25519RoundTrips()
        {
            var seed = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
                rng.GetBytes(seed);

            var gen = SshKey.FromEd25519(seed, "ed25519@interop");
            ClassicAssert.IsInstanceOf<ED25519Key>(((KeyHostAlgorithm)gen.HostKeyAlgorithms.First()).Key);
            AssertRoundTrips(gen);

            // a 64-byte expanded key (seed || public) yields the same key as its 32-byte seed
            var ed = (ED25519Key)((KeyHostAlgorithm)gen.HostKeyAlgorithms.First()).Key;
            var expanded = new byte[64];
            Buffer.BlockCopy(seed, 0, expanded, 0, 32);
            Buffer.BlockCopy(ed.PublicKey, 0, expanded, 32, 32);
            ClassicAssert.AreEqual(FpHash(gen), FpHash(SshKey.FromEd25519(expanded)));
        }

        [Test]
        public void FromEd25519RejectsBadInput()
        {
            Assert.Throws<ArgumentNullException>((Action)(() => SshKey.FromEd25519(null!)));
            Assert.Throws<ArgumentException>((Action)(() => SshKey.FromEd25519(new byte[16])));
        }

#if NET8_0_OR_GREATER
        [Test]
        public void FromPemImportsRsa()
        {
            using var rsa = RSA.Create(2048);
            var expected = FpHash(SshKey.FromKey(rsa));

            ClassicAssert.AreEqual(expected, FpHash(SshKey.FromPem(rsa.ExportPkcs8PrivateKeyPem())));
            ClassicAssert.AreEqual(expected, FpHash(SshKey.FromPem(rsa.ExportRSAPrivateKeyPem())));

            var pbe = new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 100_000);
            var enc = rsa.ExportEncryptedPkcs8PrivateKeyPem("s3cret", pbe);
            ClassicAssert.AreEqual(expected, FpHash(SshKey.FromPem(enc, "s3cret")));
            Assert.Throws<CryptographicException>((Action)(() => SshKey.FromPem(enc, "wrong")));
        }

        [Test]
        public void FromPemImportsEcdsa()
        {
            using var ecdsa = ECDsa.Create(ECCurve.CreateFromFriendlyName("nistp256"));
            var expected = FpHash(SshKey.FromKey(ecdsa));

            ClassicAssert.AreEqual(expected, FpHash(SshKey.FromPem(ecdsa.ExportPkcs8PrivateKeyPem())));
            ClassicAssert.AreEqual(expected, FpHash(SshKey.FromPem(ecdsa.ExportECPrivateKeyPem())));
        }
#else
        [Test]
        public void FromPemNotSupportedOnOldTfm()
        {
            Assert.Throws<PlatformNotSupportedException>((Action)(() => SshKey.FromPem("-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----")));
        }
#endif

        // second length-prefixed SSH string of a signature blob (string alg, string signature)
        private static byte[] SecondSshString(byte[] blob)
        {
            var len1 = (blob[0] << 24) | (blob[1] << 16) | (blob[2] << 8) | blob[3];
            var off = 4 + len1;
            var len2 = (blob[off] << 24) | (blob[off + 1] << 16) | (blob[off + 2] << 8) | blob[off + 3];
            var sig = new byte[len2];
            Buffer.BlockCopy(blob, off + 4, sig, 0, len2);
            return sig;
        }
    }
}
