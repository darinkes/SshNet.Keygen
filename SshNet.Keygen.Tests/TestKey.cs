﻿using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using NUnit.Framework;
using NUnit.Framework.Legacy;
using Renci.SshNet;
using Renci.SshNet.Security;
using SshNet.Keygen.Extensions;
using SshNet.Keygen.SshKeyEncryption;

namespace SshNet.Keygen.Tests
{
    public class TestKey
    {
        [Test]
        public void TestExceptions()
        {
            var keyInfo = new SshKeyGenerateInfo
            {
                KeyType = SshKeyType.ECDSA,
                KeyLength = 1
            };
            Assert.Throws<CryptographicException>(() => SshKey.Generate(keyInfo));

            keyInfo.KeyType = SshKeyType.RSA;
            Assert.Throws<CryptographicException>(() => SshKey.Generate(keyInfo));
        }

        [Test]
        public void TestDefaultKey()
        {
            var key = SshKey.Generate();
            ClassicAssert.IsInstanceOf<RsaKey>(((KeyHostAlgorithm)key.HostKeyAlgorithms.First()).Key);
            ClassicAssert.AreEqual(2048, ((KeyHostAlgorithm)key.HostKeyAlgorithms.First()).Key.KeyLength);
        }

        private static void KeyGenTest<TKey>(SshKeyType keyType, int keyLength = 0)
        {
            const string password = "12345";
            var comments = new[] { "", "Generated by SshNet.Keygen"};

            var sshKeyEncryptions = new List<ISshKeyEncryption>()
            {
                new SshKeyEncryptionAes256(password),
                new SshKeyEncryptionAes256(password, Aes256Mode.CBC),
                new SshKeyEncryptionAes256(password, Aes256Mode.CTR),
                new SshKeyEncryptionNone()
            };

            foreach (var comment in comments)
            {
                foreach (var path in new[] { null, "id_test"})
                {
                    foreach (var sshKeyEncryption in sshKeyEncryptions)
                    {
                        TestContext.WriteLine($"File: {path} - Encryption: {sshKeyEncryption}");

                        var keyInfo = new SshKeyGenerateInfo(keyType)
                        {
                            Encryption = sshKeyEncryption,
                            KeyLength = keyLength
                        };
                        if (!string.IsNullOrEmpty(comment))
                            keyInfo.Comment = comment;

                        var puttyKeyInfo = new SshKeyGenerateInfo(keyType)
                        {
                            KeyFormat = SshKeyFormat.PuTTY,
                            Encryption = sshKeyEncryption,
                            KeyLength = keyLength
                        };
                        if (!string.IsNullOrEmpty(comment))
                            puttyKeyInfo.Comment = comment;

                        IPrivateKeySource keyFile;
                        if (string.IsNullOrEmpty(path))
                        {
                            keyFile = SshKey.Generate(keyInfo);
                            if (keyLength != 0)
                                ClassicAssert.AreEqual(keyLength, ((KeyHostAlgorithm)keyFile.HostKeyAlgorithms.First()).Key.KeyLength);
                        }
                        else
                        {
                            _ = SshKey.Generate(path, FileMode.Create, keyInfo);
                            keyFile = new PrivateKeyFile(path, password);
                            ClassicAssert.IsTrue(File.Exists(path));

                            switch (sshKeyEncryption.CipherName)
                            {
                                case "aes256-ctr":
                                    Assert.Throws<NotSupportedException>(() => SshKey.Generate($"{path}.ppk", FileMode.Create, puttyKeyInfo));
                                    break;
                                default:
                                    File.Delete($"{path}.ppk");
                                    _ = SshKey.Generate($"{path}.ppk", FileMode.Create, puttyKeyInfo);
                                    ClassicAssert.IsTrue(File.Exists($"{path}.ppk"));
                                    break;
                            }
                        }

                        ClassicAssert.IsInstanceOf<TKey>(((KeyHostAlgorithm) keyFile.HostKeyAlgorithms.First()).Key);
                        if (keyLength != 0)
                            ClassicAssert.AreEqual(keyLength, (((KeyHostAlgorithm) keyFile.HostKeyAlgorithms.First()).Key.KeyLength));

                        ClassicAssert.AreEqual(
                            string.IsNullOrEmpty(comment)
                                ? $"{Environment.UserName}@{Environment.MachineName}"
                                : comment,
                            ((KeyHostAlgorithm) keyFile.HostKeyAlgorithms.First()).Key.Comment);
                    }
                }
            }
        }

        [Test]
        public void GenerateED25519Key()
        {
            KeyGenTest<ED25519Key>(SshKeyType.ED25519);
        }

        [Test]
        public void GenerateRSA2048()
        {
            KeyGenTest<RsaKey>(SshKeyType.RSA, 2048);
        }

        [Test]
        public void GenerateRSA3072()
        {
            KeyGenTest<RsaKey>(SshKeyType.RSA, 3072);
        }

        [Test]
        public void GenerateRSA4096()
        {
            KeyGenTest<RsaKey>(SshKeyType.RSA, 4096);
        }

        // Nothing wrong with it, just super slow.
        // [Test]
        // public void GenerateRSA8192()
        // {
        //     KeyGenTest<RsaKey>(SshKeyType.RSA, 8192);
        // }

        [Test]
        public void GenerateEcdsa256()
        {
            KeyGenTest<EcdsaKey>(SshKeyType.ECDSA, 256);
        }

        [Test]
        public void GenerateEcdsa384()
        {
            KeyGenTest<EcdsaKey>(SshKeyType.ECDSA, 384);
        }

        [Test]
        public void GenerateEcdsa521()
        {
            KeyGenTest<EcdsaKey>(SshKeyType.ECDSA, 521);
        }

        private string GetKey(string keyname)
        {
            var resourceStream = Assembly.GetExecutingAssembly().GetManifestResourceStream($"SshNet.Keygen.Tests.TestKeys.{keyname}");
            using var reader = new StreamReader(resourceStream, Encoding.ASCII);
            return reader.ReadToEnd();
        }

        private void TestFormatKey<T>(string keyname, int keyLength, string passphrase = null)
        {
            if (!string.IsNullOrEmpty(passphrase))
                keyname = $"{keyname}.encrypted";

            var keydata = GetKey(keyname);
            var pubkeydata = GetKey($"{keyname}.pub");
            var fpMd5Data = GetKey($"{keyname}.fingerprint.md5");
            var fpSha1Data = GetKey($"{keyname}.fingerprint.sha1");
            var fpSha256Data = GetKey($"{keyname}.fingerprint.sha256");
            var fpSha384Data = GetKey($"{keyname}.fingerprint.sha384");
            var fpSha512Data = GetKey($"{keyname}.fingerprint.sha512");
            var keyFile = new PrivateKeyFile(keydata.ToStream(), passphrase);

            var key = ((KeyHostAlgorithm) keyFile.HostKeyAlgorithms.First()).Key;

            ClassicAssert.IsInstanceOf<T>(key);
            ClassicAssert.AreEqual(keyLength, key.KeyLength);
            ClassicAssert.AreEqual(pubkeydata.Trim(), keyFile.ToPublic().Trim());
            ClassicAssert.AreEqual(fpSha256Data.Trim(), keyFile.Fingerprint().Trim());
            ClassicAssert.AreEqual(fpMd5Data.Trim(), keyFile.Fingerprint(SshKeyHashAlgorithmName.MD5).Trim());
            ClassicAssert.AreEqual(fpSha1Data.Trim(), keyFile.Fingerprint(SshKeyHashAlgorithmName.SHA1).Trim());
            ClassicAssert.AreEqual(fpSha256Data.Trim(), keyFile.Fingerprint(SshKeyHashAlgorithmName.SHA256).Trim());
            ClassicAssert.AreEqual(fpSha384Data.Trim(), keyFile.Fingerprint(SshKeyHashAlgorithmName.SHA384).Trim());
            ClassicAssert.AreEqual(fpSha512Data.Trim(), keyFile.Fingerprint(SshKeyHashAlgorithmName.SHA512).Trim());

            // We cannot test the result of the PrivateKey Export, since Random CheckInts are random...
            // So just check the key can be reimport again.
            // Assert.AreEqual(keydata.Trim(), keyFile.ToOpenSshFormat().Trim());
            var export = string.IsNullOrEmpty(passphrase)
                ? keyFile.ToOpenSshFormat()
                : keyFile.ToOpenSshFormat(new SshKeyEncryptionAes256(passphrase));
            Assert.DoesNotThrow(() =>
            {
                _ = new PrivateKeyFile(export.ToStream(), passphrase);
            });
        }

        [Test]
        public void TestRSA2048()
        {
            TestFormatKey<RsaKey>("RSA2048", 2048);
            TestFormatKey<RsaKey>("RSA2048", 2048, "12345");
        }

        [Test]
        public void TestRSA3072()
        {
            TestFormatKey<RsaKey>("RSA3072", 3072);
            TestFormatKey<RsaKey>("RSA3072", 3072, "12345");
        }

        [Test]
        public void TestRSA4096()
        {
            TestFormatKey<RsaKey>("RSA4096", 4096);
            TestFormatKey<RsaKey>("RSA4096", 4096, "12345");
        }

        [Test]
        public void TestRSA8192()
        {
            TestFormatKey<RsaKey>("RSA8192", 8192);
            TestFormatKey<RsaKey>("RSA8192", 8192, "12345");
        }

        [Test]
        public void TestECDSA256()
        {
            TestFormatKey<EcdsaKey>("ECDSA256", 256);
            TestFormatKey<EcdsaKey>("ECDSA256", 256, "12345");
        }

        [Test]
        public void TestECDSA384()
        {
            TestFormatKey<EcdsaKey>("ECDSA384", 384);
            TestFormatKey<EcdsaKey>("ECDSA384", 384, "12345");
        }

        [Test]
        public void TestECDSA521()
        {
            TestFormatKey<EcdsaKey>("ECDSA521", 521);
            TestFormatKey<EcdsaKey>("ECDSA521", 521, "12345");
        }

        [Test]
        public void TestED25519()
        {
            TestFormatKey<ED25519Key>("ED25519", 256);
            TestFormatKey<ED25519Key>("ED25519", 256, "12345");
        }
    }
}