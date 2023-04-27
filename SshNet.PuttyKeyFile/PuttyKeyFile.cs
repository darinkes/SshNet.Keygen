using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Renci.SshNet;
using Renci.SshNet.Common;
using Renci.SshNet.Security;
using Renci.SshNet.Security.Cryptography.Ciphers;
using Renci.SshNet.Security.Cryptography.Ciphers.Modes;
using Renci.SshNet.Security.Cryptography.Ciphers.Paddings;
using SshNet.PuttyKeyFile.Extensions;
using Konscious.Security.Cryptography;

namespace SshNet.PuttyKeyFile
{
    public class PuttyKeyFile : IPrivateKeySource
    {
        // PPK file format: https://tartarus.org/~simon/putty-snapshots/htmldoc/AppendixC.html

        private static readonly Regex PuttyPrivateKeyRegex = new(
            @"^PuTTY-User-Key-File-(?<fileVersion>[0-9]+): *(?<keyType>[^\r\n]+)(\r|\n)+" +
            @"Encryption: *(?<encryption>[^\r\n]+)(\r|\n)+" +
            @"Comment: *(?<comment>[^\r\n]+)(\r|\n)+" +
            @"Public-Lines: *([0-9]+)(\r|\n)+" +
            @"(?<publicLines>([a-zA-Z0-9/+=]{1,80}(\r|\n)+)+)" +
            @"(?>Key-Derivation: *(?<keyDerivation>[^\r\n]+)(\r|\n)+)?" + // Putty3
            @"(?>Argon2-Memory: *(?<argon2Memory>[^\r\n]+)(\r|\n)+)?" + // Putty3
            @"(?>Argon2-Passes: *(?<argon2Passes>[^\r\n]+)(\r|\n)+)?" + // Putty3
            @"(?>Argon2-Parallelism: *(?<argon2Parallelism>[^\r\n]+)(\r|\n)+)?" + // Putty3
            @"(?>Argon2-Salt: *(?<argon2Salt>[^\r\n]+)(\r|\n)+)?" + // Putty3
            @"Private-Lines: *([0-9]+)(\r|\n)+" +
            @"(?<privateLines>([a-zA-Z0-9/+=]{1,80}(\r|\n)+)+)" +
            @"Private-(?<macOrHash>(MAC|Hash)): *(?<hashData>[a-zA-Z0-9/+=]+)",
            RegexOptions.Compiled | RegexOptions.Multiline);

        private readonly List<HostAlgorithm> _hostAlgorithms = new();

        public IReadOnlyCollection<HostAlgorithm> HostKeyAlgorithms => _hostAlgorithms;

        public Key Key { get; private set; }

        public PuttyKeyFile(Stream privateKey)
        {
            Open(privateKey, null);
        }

        public PuttyKeyFile(string fileName, string? passPhrase = null)
        {
            using var keyFile = File.Open(fileName, FileMode.Open, FileAccess.Read, FileShare.Read);
            Open(keyFile, passPhrase);
        }

        public PuttyKeyFile(Stream privateKey, string? passPhrase)
        {
            Open(privateKey, passPhrase);
        }

        public static bool IsPuttyPrivateKey(string keyText)
        {
            var privateKeyMatch = PuttyPrivateKeyRegex.Match(keyText);
            return privateKeyMatch.Success;
        }

        private void Open(Stream privateKey, string? passPhrase)
        {
            using var streamReader = new StreamReader(privateKey);
            var keyText = streamReader.ReadToEnd();

            var privateKeyMatch = PuttyPrivateKeyRegex.Match(keyText);
            if (!privateKeyMatch.Success)
            {
                throw new SshException("Invalid PuTTY private key file.");
            }

            var fileVersion = Convert.ToInt32(privateKeyMatch.Result("${fileVersion}"));
            var keyType = privateKeyMatch.Result("${keyType}");
            var encryption = privateKeyMatch.Result("${encryption}");
            var comment = privateKeyMatch.Result("${comment}");
            var publicLines = privateKeyMatch.Result("${publicLines}");
            var privateLines = privateKeyMatch.Result("${privateLines}");
            var macOrHash = privateKeyMatch.Result("${macOrHash}");
            var hashData = privateKeyMatch.Result("${hashData}");

            var keyDerivation = privateKeyMatch.Result("${keyDerivation}");
            var argon2Memory = privateKeyMatch.Result("${argon2Memory}");
            var argon2Passes = privateKeyMatch.Result("${argon2Passes}");
            var argon2Parallelism = privateKeyMatch.Result("${argon2Parallelism}");
            var argon2Salt = privateKeyMatch.Result("${argon2Salt}");

            if (string.IsNullOrEmpty(encryption))
                throw new SshException("PuTTY private key file encryption was empty");

            var publicKeyData = Convert.FromBase64String(publicLines);

            var macKey3 = new List<byte>();
            byte[] unencryptedPrivateKeyData;
            switch (encryption)
            {
                case "none":
                {
                    passPhrase = null;
                    unencryptedPrivateKeyData = Convert.FromBase64String(privateLines);
                    break;
                }
                case "aes256-cbc":
                {
                    if (string.IsNullOrEmpty(passPhrase))
                        throw new SshPassPhraseNullOrEmptyException("Private key is encrypted but passphrase is empty.");

                    switch (fileVersion)
                    {
                        case 2:
                        {
                            var cipherKey = GetCipherKey(passPhrase, 32);
                            var cipher = new AesCipher(cipherKey, new CbcCipherMode(new byte[cipherKey.Length]),
                                new PKCS7Padding());

                            var privateKeyData = Convert.FromBase64String(privateLines);
                            if (privateKeyData.Length % cipher.BlockSize != 0)
                                throw new SshException("Private key data not multiple of cipher block size.");

                            unencryptedPrivateKeyData = cipher.Decrypt(privateKeyData);
                            break;
                        }
                        case 3:
                        {
                            Argon2 argon2;
                            var passphraseBytes = Encoding.UTF8.GetBytes(passPhrase);
                            switch (keyDerivation)
                            {
                                case "Argon2d":
                                    argon2 = new Argon2d(passphraseBytes);
                                    break;
                                case "Argon2i":
                                    argon2 = new Argon2i(passphraseBytes);
                                    break;
                                case "Argon2id":
                                    argon2 = new Argon2id(passphraseBytes);
                                    break;
                                default:
                                    throw new SshException($"Encryption Key Derivation {keyDerivation} is not supported.");
                            }

                            argon2.DegreeOfParallelism = int.Parse(argon2Parallelism);
                            argon2.MemorySize = int.Parse(argon2Memory);
                            argon2.Iterations = int.Parse(argon2Passes);
                            argon2.Salt = StringToByteArray(argon2Salt);

                            // Argon2 takes two extra string inputs in addition to the passphrase and the salt: a secret key, and some ‘associated data’. In PPK's use of Argon2, these are both set to the empty string.
                            //argon2.KnownSecret = new byte[0];
                            //argon2.AssociatedData = new byte[0];

                            //So, for ‘aes256-cbc’, the tag length will be 32+16+32 = 80 bytes; of the 80 bytes of output data,
                            // the first 32 bytes are used as the 256-bit AES key,
                            // the next 16 as the CBC IV,
                            // and the final 32 bytes as the HMAC-SHA-256 key.
                            var cipherKeyComplete = argon2.GetBytes(80);

                            var cipherKey = new byte[32];
                            var crcIv = new byte[16];
                            var macKey = new byte[32];
                            Buffer.BlockCopy(cipherKeyComplete, 0, cipherKey, 0, cipherKey.Length);
                            Buffer.BlockCopy(cipherKeyComplete, 32, crcIv, 0, crcIv.Length);
                            Buffer.BlockCopy(cipherKeyComplete, 48, macKey, 0, macKey.Length);
                            macKey3.Clear();
                            macKey3.AddRange(macKey);

                            var cipher = new AesCipher(cipherKey, new CbcCipherMode(crcIv), new PKCS7Padding());

                            var privateKeyData = Convert.FromBase64String(privateLines);
                            if (privateKeyData.Length % cipher.BlockSize != 0)
                                throw new SshException("Private key data not multiple of cipher block size.");

                            unencryptedPrivateKeyData = cipher.Decrypt(privateKeyData);
                            break;
                        }
                        default:
                        {
                            throw new SshException($"Encryption {encryption} is not supported.");
                        }
                    }

                    break;
                }
                default:
                {
                    throw new SshException($"Encryption {encryption} is not supported.");
                }
            }

            byte[] macData;
            switch (fileVersion)
            {
                case 1:
                    macData = unencryptedPrivateKeyData;
                    break;
                case 2:
                case 3:
                {
                    using var data = new SshDataStream(0);
                    data.Write(keyType, Encoding.UTF8);
                    data.Write(encryption, Encoding.UTF8);
                    data.Write(comment, Encoding.UTF8);
                    data.WriteBinary(publicKeyData);
                    data.WriteBinary(unencryptedPrivateKeyData);
                    macData = data.ToArray();
                    break;
                }
                default:
                    throw new NotSupportedException($"PuTTY private key file version {fileVersion} is not supported.");
            }

            byte[] macOrHashData;
            switch (macOrHash.ToLower())
            {
                case "mac":
                {
                    switch (fileVersion)
                    {
                        case 2:
                        {
                            using var sha1 = SHA1.Create();
                            var macKey = sha1.ComputeHash(Encoding.UTF8.GetBytes("putty-private-key-file-mac-key" + passPhrase));
                            using var hmac = new HMACSHA1(macKey);
                            macOrHashData = hmac.ComputeHash(macData);
                            break;
                        }
                        case 3:
                        {
                            using var hmac = new HMACSHA256(macKey3.ToArray());
                            macOrHashData = hmac.ComputeHash(macData);
                            break;
                        }
                        default:
                            throw new NotSupportedException($"Private key verification algorithm {macOrHash} not supported for file version {fileVersion}");
                    }

                    break;
                }
                case "hash" when fileVersion == 1:
                {
                    using var sha1 = SHA1.Create();
                    macOrHashData = sha1.ComputeHash(macData);
                    break;
                }
                default:
                    throw new NotSupportedException($"Private key verification algorithm {macOrHash} not supported for file version {fileVersion}");
            }

            if (BitConverter.ToString(macOrHashData).Replace("-", "").ToLower() != hashData)
            {
                throw new SshException("Invalid PuTTY private key");
            }

            var publicKeyReader = new SshDataReader(publicKeyData);
            var privateKeyReader = new SshDataReader(unencryptedPrivateKeyData);
            var pubKeyType = publicKeyReader.ReadString(Encoding.UTF8);

            if (pubKeyType != keyType)
            {
                throw new SshException($"PuTTY Public Key Type '{pubKeyType}' and Private Key Type '{keyType}' differ");
            }

            Key parsedKey;
            byte[] publicKey;
            byte[] unencryptedPrivateKey;
            switch (keyType)
            {
                case "ssh-ed25519":
                    publicKey = publicKeyReader.ReadBignum2();
                    unencryptedPrivateKey = privateKeyReader.ReadBignum2();
                    parsedKey = new ED25519Key(publicKey.Reverse(), unencryptedPrivateKey);
                    break;
                case "ecdsa-sha2-nistp256":
                case "ecdsa-sha2-nistp384":
                case "ecdsa-sha2-nistp521":
                    var len = (int)publicKeyReader.ReadUInt32();
                    var curve = Encoding.ASCII.GetString(publicKeyReader.ReadBytes(len));
                    publicKey = publicKeyReader.ReadBignum2();
                    unencryptedPrivateKey = privateKeyReader.ReadBignum2();
                    parsedKey = new EcdsaKey(curve, publicKey, unencryptedPrivateKey.TrimLeadingZeros());
                    break;
                case "ssh-rsa":
                    var exponent = publicKeyReader.ReadBigIntWithBytes();
                    var modulus = publicKeyReader.ReadBigIntWithBytes();
                    var d = privateKeyReader.ReadBigIntWithBytes();
                    var p = privateKeyReader.ReadBigIntWithBytes();
                    var q = privateKeyReader.ReadBigIntWithBytes();
                    var inverseQ = privateKeyReader.ReadBigIntWithBytes();
                    parsedKey = new RsaKey(modulus, exponent, d, p, q, inverseQ);
                    break;
                default:
                    throw new SshException("PuTTY key type '" + keyType + "' is not supported.");
            }

            parsedKey.Comment = comment;

            Key = parsedKey;
            _hostAlgorithms.Add(new KeyHostAlgorithm(parsedKey.ToString(), parsedKey));
        }


        private static byte[] StringToByteArray(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                .Where(x => x % 2 == 0)
                .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                .ToArray();
        }

        private static byte[] GetCipherKey(string? passphrase, int length)
        {
            var cipherKey = new List<byte>();

            using var sha1 = SHA1.Create();
            if (passphrase is null)
                throw new ArgumentNullException(nameof(passphrase));
            var passphraseBytes = Encoding.UTF8.GetBytes(passphrase);

            var counter = 0;
            do {
                var counterBytes = BitConverter.GetBytes(counter++);
                if (BitConverter.IsLittleEndian)
                    Array.Reverse(counterBytes);

                var hashBytes = new byte[counterBytes.Length + passphraseBytes.Length];
                Buffer.BlockCopy(counterBytes, 0, hashBytes, 0, counterBytes.Length);
                Buffer.BlockCopy(passphraseBytes, 0, hashBytes, counterBytes.Length, passphraseBytes.Length);

                var hash = sha1.ComputeHash(hashBytes);
                cipherKey.AddRange(hash);
            } while (cipherKey.Count < length);

            var returnBytes = new byte[length];
            Buffer.BlockCopy(cipherKey.ToArray(), 0, returnBytes, 0, length);
            return returnBytes;
        }
    }

    public class SshDataReader : SshData
    {
        public SshDataReader(byte[] data)
        {
            Load(data);
        }

        public new uint ReadUInt32()
        {
            return base.ReadUInt32();
        }

        public new string ReadString(Encoding encoding)
        {
            return base.ReadString(encoding);
        }

        public new byte[] ReadBytes(int length)
        {
            return base.ReadBytes(length);
        }

        public BigInteger ReadBigIntWithBytes()
        {
            var length = (int)base.ReadUInt32();

            var data = base.ReadBytes(length);
            var bytesArray = new byte[data.Length + 1];
            Buffer.BlockCopy(data, 0, bytesArray, 1, data.Length);

            return new BigInteger(bytesArray.Reverse());
        }

        public byte[] ReadBignum2()
        {
            var length = (int)base.ReadUInt32();
            return base.ReadBytes(length);
        }

        protected override void LoadData()
        {
        }

        protected override void SaveData()
        {
        }
    }
}