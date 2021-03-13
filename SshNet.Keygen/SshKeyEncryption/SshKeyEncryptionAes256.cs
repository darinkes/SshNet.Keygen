using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Renci.SshNet.Security.Cryptography.Ciphers;
using Renci.SshNet.Security.Cryptography.Ciphers.Modes;
using Renci.SshNet.Security.Cryptography.Ciphers.Paddings;
using SshNet.Keygen.Extensions;

namespace SshNet.Keygen.SshKeyEncryption
{
    public enum Aes256Mode
    {
        CBC,
        CTR
    }

    public class SshKeyEncryptionAes256 : ISshKeyEncryption
    {
        public string CipherName => $"aes256-{_mode.ToString().ToLower()}";
        public string KdfName => "bcrypt";
        public int BlockSize => 16;
        public string Passphrase => _passphrase;

        private const int SaltLen = 16;
        private const int Rounds = 16;
        private Aes256Mode _mode;
        private readonly byte[] _passPhraseBytes;
        private readonly byte[] _salt;
        private readonly string _passphrase;

        public SshKeyEncryptionAes256(string passphrase)
        {
            _passphrase = passphrase;
            _passPhraseBytes = Encoding.ASCII.GetBytes(passphrase);
            _salt = new byte[SaltLen];
        }

        public SshKeyEncryptionAes256(string passphrase, Aes256Mode mode) : this(passphrase)
        {
            _mode = mode;
        }

        public byte[] KdfOptions()
        {
            using var stream = new MemoryStream();
            using var writer = new BinaryWriter(stream);
            using var rng = new RNGCryptoServiceProvider();
            rng.GetBytes(_salt);
            writer.EncodeString(_salt);
            writer.EncodeUInt(Rounds);
            return stream.ToArray();
        }

        public byte[] Encrypt(byte[] data)
        {
            var keyiv = new byte[48];
            new BCrypt().Pbkdf(_passPhraseBytes, _salt, Rounds, keyiv);
            var key = new byte[32];
            var iv = new byte[16];
            Array.Copy(keyiv, 0, key, 0, 32);
            Array.Copy(keyiv, 32, iv, 0, 16);

            AesCipher cipher;
            switch(_mode)
            {
                case Aes256Mode.CBC:
                    cipher = new AesCipher(key, new CbcCipherMode(iv), new PKCS7Padding());
                    break;
                default:
                    _mode = Aes256Mode.CTR;
                    cipher = new AesCipher(key, new CtrCipherMode(iv), new PKCS7Padding());
                    break;
            }

            return cipher.Encrypt(data);
        }

        public byte[] Encrypt(byte[] data, int offset, int length)
        {
            var buffer = new byte[length];
            Array.Copy(data, offset, buffer, 0, length);
            return Encrypt(buffer);
        }

        public byte[] PuttyEncrypt(byte[] data)
        {
            using var sha1 = SHA1.Create();

            var cipherKeyList = new List<byte>();
            var counter = 0;
            do {
                var counterBytes = BitConverter.GetBytes(counter++);
                if (BitConverter.IsLittleEndian)
                    Array.Reverse(counterBytes);

                var hashBytes = new byte[counterBytes.Length + _passPhraseBytes.Length];
                Buffer.BlockCopy(counterBytes, 0, hashBytes, 0, counterBytes.Length);
                Buffer.BlockCopy(_passPhraseBytes, 0, hashBytes, counterBytes.Length, _passPhraseBytes.Length);

                var hash = sha1.ComputeHash(hashBytes);
                cipherKeyList.AddRange(hash);
            } while (cipherKeyList.Count < 32);

            var cipherKey = new byte[32];
            Array.Copy(cipherKeyList.ToArray(), 0, cipherKey, 0, 32);

            AesCipher cipher;
            switch(_mode)
            {
                case Aes256Mode.CTR:
                    throw new NotSupportedException($"Unsupported AES Mode: {_mode}");
                default:
                    _mode = Aes256Mode.CBC;
                    cipher = new AesCipher(cipherKey, new CbcCipherMode(new byte[cipherKey.Length]), new PKCS7Padding());
                    break;
            };
            return cipher.Encrypt(data);
        }

        public byte[] PuttyEncrypt(byte[] data, int offset, int length)
        {
            var buffer = new byte[length];
            Array.Copy(data, offset, buffer, 0, length);
            return PuttyEncrypt(buffer);
        }
    }
}