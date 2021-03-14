using System;
using System.IO;
using System.Reflection;
using NUnit.Framework;
using Renci.SshNet.Security;

namespace SshNet.PuttyKey.Tests
{
    public class Tests
    {
        [SetUp]
        public void Setup()
        {
        }

        private void TestKey<TKey>(string keyName, string comment, int keyLength = 0, string? pass = null) where TKey : Key, new()
        {
            var keyStream = GetKey($"{keyName}.ppk");
            if (keyStream is null)
                throw new NullReferenceException(nameof(keyStream));

            var keyFile = new PuttyKeyFile(keyStream, pass);

            Assert.IsInstanceOf<TKey>(((KeyHostAlgorithm) keyFile.HostKey).Key);
            Assert.AreEqual(keyLength, ((KeyHostAlgorithm) keyFile.HostKey).Key.KeyLength);
            Assert.AreEqual(comment, ((KeyHostAlgorithm) keyFile.HostKey).Key.Comment);
        }

        [Test]
        public void Test_RSA2048()
        {
            TestKey<RsaKey>("rsa2048", "rsa-key-20210312", 2048);
            TestKey<RsaKey>("rsa2048pass", "rsa-key-20210312", 2048, "12345");
        }

        [Test]
        public void Test_RSA3072()
        {
            TestKey<RsaKey>("rsa3072", "rsa-key-20210312", 3072);
            TestKey<RsaKey>("rsa3072pass", "rsa-key-20210312", 3072, "12345");
        }

        [Test]
        public void Test_RSA4096()
        {
            TestKey<RsaKey>("rsa4096", "rsa-key-20210312", 4096);
            TestKey<RsaKey>("rsa4096pass", "rsa-key-20210312", 4096, "12345");
        }

        [Test]
        public void Test_RSA8192()
        {
            TestKey<RsaKey>("rsa8192", "rsa-key-20210312", 8192);
            TestKey<RsaKey>("rsa8192pass", "rsa-key-20210312", 8192, "12345");
        }

        [Test]
        public void Test_ECDSA256()
        {
            TestKey<EcdsaKey>("ecdsa256", "ecdsa-key-20210312", 256);
            TestKey<EcdsaKey>("ecdsa256pass", "ecdsa-key-20210312", 256, "12345");
        }

        [Test]
        public void Test_ECDSA384()
        {
            TestKey<EcdsaKey>("ecdsa384", "ecdsa-key-20210312", 384);
            TestKey<EcdsaKey>("ecdsa384pass", "ecdsa-key-20210312", 384, "12345");
        }

        [Test]
        public void Test_ECDSA521()
        {
            TestKey<EcdsaKey>("ecdsa521", "ecdsa-key-20210312", 521);
            TestKey<EcdsaKey>("ecdsa521pass", "ecdsa-key-20210312", 521, "12345");
        }

        [Test]
        public void Test_ED25519()
        {
            TestKey<ED25519Key>("ed25519", "ed25519-key-20210312", 256);
            TestKey<ED25519Key>("ed25519pass", "ed25519-key-20210312", 256, "12345");
        }

        private static Stream? GetKey(string keyName)
        {
            return Assembly.GetExecutingAssembly().GetManifestResourceStream($"SshNet.PuttyKey.Tests.TestKeys.{keyName}");
        }
    }
}