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

            var key = SshKey.Generate();
            Assert.Throws<NotSupportedException>(() => key.ToPuttyFormat(SshKeyFormat.OpenSSH));
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
                        TestContext.WriteLine($"File: '{path}' - Encryption: '{sshKeyEncryption}' - Comment: '{comment}'");

                        var keyInfo = new SshKeyGenerateInfo(keyType)
                        {
                            Encryption = sshKeyEncryption,
                            KeyLength = keyLength,
                            Comment = comment
                        };

                        IPrivateKeySource keyFile;
                        if (string.IsNullOrEmpty(path))
                        {
                            keyFile = SshKey.Generate(keyInfo);
                            if (keyLength != 0)
                                ClassicAssert.AreEqual(keyLength, ((KeyHostAlgorithm)keyFile.HostKeyAlgorithms.First()).Key.KeyLength);
                        }
                        else
                        {
                            var genKey = SshKey.Generate(path, FileMode.Create, keyInfo);
                            ClassicAssert.IsTrue(File.Exists(path));
                            keyFile = new PrivateKeyFile(path, password);
                            _ = new PrivateKeyFile(genKey.ToOpenSshFormat().ToStream(), password);

                            ClassicAssert.AreEqual(genKey.ToOpenSshPublicFormat(), genKey.ToPublic());
                            ClassicAssert.AreEqual(genKey.ToOpenSshPublicFormat(), keyFile.ToPublic());
                            ClassicAssert.AreEqual(1, genKey.ToPublic().Split('\n').Length - 1);
                            ClassicAssert.AreEqual(1, keyFile.ToPublic().Split('\n').Length - 1);

                            StringAssert.Contains(((KeyHostAlgorithm) genKey.HostKeyAlgorithms.First()).Key.ToString(), genKey.ToPublic());
                            StringAssert.Contains(comment ?? SshKeyGenerateInfo.DefaultSshKeyComment, genKey.ToPublic());
                            StringAssert.Contains(((KeyHostAlgorithm) genKey.HostKeyAlgorithms.First()).Key.ToString(), genKey.ToOpenSshPublicFormat());
                            StringAssert.Contains(comment ?? SshKeyGenerateInfo.DefaultSshKeyComment, genKey.ToOpenSshPublicFormat());

                            foreach (var keyFormat in new List<SshKeyFormat> { SshKeyFormat.PuTTYv2 , SshKeyFormat.PuTTYv3 })
                            {
                                keyInfo.KeyFormat = keyFormat;
                                var puttyFile = $"{path}-{keyFormat}.ppk";

                                switch (sshKeyEncryption.CipherName)
                                {
                                    case "aes256-ctr":
                                        Assert.Throws<NotSupportedException>(() => SshKey.Generate(puttyFile, FileMode.Create, keyInfo));
                                        break;
                                    default:
                                        File.Delete(puttyFile);
                                        var puttyKey = SshKey.Generate(puttyFile, FileMode.Create, keyInfo);
                                        ClassicAssert.IsTrue(File.Exists(puttyFile));

                                        foreach (var puttyContent in new List<string> { File.ReadAllText(puttyFile), puttyKey.ToPuttyFormat() })
                                        {
                                            StringAssert.Contains($"Comment: {comment ?? SshKeyGenerateInfo.DefaultSshKeyComment}", puttyContent);
                                            StringAssert.Contains($"Encryption: {sshKeyEncryption.CipherName}", puttyContent);

                                            switch (keyFormat)
                                            {
                                                case SshKeyFormat.PuTTYv2:
                                                    StringAssert.Contains("PuTTY-User-Key-File-2: ", puttyContent);
                                                    break;
                                                case SshKeyFormat.PuTTYv3:
                                                    StringAssert.Contains("PuTTY-User-Key-File-3: ", puttyContent);
                                                    if (keyInfo.Encryption is SshKeyEncryptionAes256)
                                                    {
                                                        StringAssert.Contains("Key-Derivation: Argon2id", puttyContent);
                                                        StringAssert.Contains("Argon2-Memory: 8192", puttyContent);
                                                        StringAssert.Contains("Argon2-Passes: 22", puttyContent);
                                                        StringAssert.Contains("Argon2-Parallelism: 1", puttyContent);
                                                        StringAssert.Contains("Argon2-Salt:", puttyContent);
                                                    }
                                                    break;
                                            }
                                        }

                                        var puttyPubContent = puttyKey.ToPuttyPublicFormat();
                                        ClassicAssert.AreEqual(puttyPubContent, puttyKey.ToPublic());
                                        StringAssert.Contains("---- BEGIN SSH2 PUBLIC KEY ----\n", puttyPubContent);
                                        StringAssert.Contains($"Comment: \"{comment ?? SshKeyGenerateInfo.DefaultSshKeyComment}\"\n", puttyPubContent);
                                        StringAssert.Contains("---- END SSH2 PUBLIC KEY ----\n", puttyPubContent);
                                        break;
                                }
                            }
                        }

                        ClassicAssert.IsInstanceOf<TKey>(((KeyHostAlgorithm) keyFile.HostKeyAlgorithms.First()).Key);
                        if (keyLength != 0)
                            ClassicAssert.AreEqual(keyLength, (((KeyHostAlgorithm) keyFile.HostKeyAlgorithms.First()).Key.KeyLength));

                        ClassicAssert.AreEqual(comment ?? SshKeyGenerateInfo.DefaultSshKeyComment,
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