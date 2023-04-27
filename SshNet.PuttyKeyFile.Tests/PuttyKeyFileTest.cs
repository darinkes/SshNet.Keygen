using System;
using System.IO;
using System.Linq;
using System.Reflection;
using NUnit.Framework;
using Renci.SshNet.Security;

namespace SshNet.PuttyKeyFile.Tests
{
    public class PuttyKeyFileTest
    {
        [SetUp]
        public void Setup()
        {
        }

        private void TestKey<TKey>(string keyName, string versionSuffix, string comment, int keyLength = 0, string? pass = null) where TKey : Key, new()
        {
            var keyStream = GetKey($"{keyName}-v{versionSuffix}.ppk");
            if (keyStream is null)
                throw new NullReferenceException(nameof(keyStream));

            var keyFile = new PuttyKeyFile(keyStream, pass);

            Assert.IsInstanceOf<TKey>(((KeyHostAlgorithm) keyFile.HostKeyAlgorithms.First()).Key);
            Assert.AreEqual(keyLength, ((KeyHostAlgorithm) keyFile.HostKeyAlgorithms.First()).Key.KeyLength);
            Assert.AreEqual(comment, ((KeyHostAlgorithm) keyFile.HostKeyAlgorithms.First()).Key.Comment);
        }

        [Test]
        public void Test_RSA2048()
        {
            TestKey<RsaKey>("rsa2048", "2", "rsa-key-20210312", 2048);
            TestKey<RsaKey>("rsa2048pass", "2", "rsa-key-20210312", 2048, "12345");
            TestKey<RsaKey>("rsa2048", "3", "rsa-key-20210312", 2048);
            TestKey<RsaKey>("rsa2048pass", "3", "rsa-key-20210312", 2048, "12345");
        }

        [Test]
        public void Test_RSA3072()
        {
            TestKey<RsaKey>("rsa3072", "2", "rsa-key-20210312", 3072);
            TestKey<RsaKey>("rsa3072pass", "2", "rsa-key-20210312", 3072, "12345");
            TestKey<RsaKey>("rsa3072", "3", "rsa-key-20210312", 3072);
            TestKey<RsaKey>("rsa3072pass", "3", "rsa-key-20210312", 3072, "12345");
        }

        [Test]
        public void Test_RSA4096()
        {
            TestKey<RsaKey>("rsa4096", "2", "rsa-key-20210312", 4096);
            TestKey<RsaKey>("rsa4096pass", "2", "rsa-key-20210312", 4096, "12345");
            TestKey<RsaKey>("rsa4096", "3", "rsa-key-20210312", 4096);
            TestKey<RsaKey>("rsa4096pass", "3", "rsa-key-20210312", 4096, "12345");
        }

        [Test]
        public void Test_RSA8192()
        {
            TestKey<RsaKey>("rsa8192", "2", "rsa-key-20210312", 8192);
            TestKey<RsaKey>("rsa8192pass", "2", "rsa-key-20210312", 8192, "12345");
            TestKey<RsaKey>("rsa8192", "3", "rsa-key-20210312", 8192);
            TestKey<RsaKey>("rsa8192pass", "3", "rsa-key-20210312", 8192, "12345");
        }

        [Test]
        public void Test_ECDSA256()
        {
            TestKey<EcdsaKey>("ecdsa256", "2", "ecdsa-key-20210312", 256);
            TestKey<EcdsaKey>("ecdsa256pass", "2", "ecdsa-key-20210312", 256, "12345");
            TestKey<EcdsaKey>("ecdsa256", "3", "ecdsa-key-20210312", 256);
            TestKey<EcdsaKey>("ecdsa256pass","3", "ecdsa-key-20210312", 256, "12345");
        }

        [Test]
        public void Test_ECDSA384()
        {
            TestKey<EcdsaKey>("ecdsa384", "2", "ecdsa-key-20210312", 384);
            TestKey<EcdsaKey>("ecdsa384pass", "2", "ecdsa-key-20210312", 384, "12345");
            TestKey<EcdsaKey>("ecdsa384", "3", "ecdsa-key-20210312", 384);
            TestKey<EcdsaKey>("ecdsa384pass", "3", "ecdsa-key-20210312", 384, "12345");
        }

        [Test]
        public void Test_ECDSA521()
        {
            TestKey<EcdsaKey>("ecdsa521", "2", "ecdsa-key-20210312", 521);
            TestKey<EcdsaKey>("ecdsa521pass", "2", "ecdsa-key-20210312", 521, "12345");
            TestKey<EcdsaKey>("ecdsa521", "3", "ecdsa-key-20210312", 521);
            TestKey<EcdsaKey>("ecdsa521pass", "3", "ecdsa-key-20210312", 521, "12345");
        }

        [Test]
        public void Test_ED25519()
        {
            TestKey<ED25519Key>("ed25519", "2", "ed25519-key-20210312", 256);
            TestKey<ED25519Key>("ed25519pass", "2", "ed25519-key-20210312", 256, "12345");
            TestKey<ED25519Key>("ed25519", "3", "ed25519-key-20210312", 256);
            TestKey<ED25519Key>("ed25519pass", "3", "ed25519-key-20210312", 256, "12345");
        }

        private static Stream? GetKey(string keyName)
        {
            return Assembly.GetExecutingAssembly().GetManifestResourceStream($"SshNet.PuttyKeyFile.Tests.TestKeys.{keyName}");
        }
    }
}