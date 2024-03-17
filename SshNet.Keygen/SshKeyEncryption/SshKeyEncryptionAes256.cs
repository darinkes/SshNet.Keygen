using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Konscious.Security.Cryptography;
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
        public PuttyV3Encryption PuttyV3Encryption => _puttyV3Encryption;

        private const int SaltLen = 16;
        private const int Rounds = 16;
        private Aes256Mode _mode;
        private readonly byte[] _passPhraseBytes;
        private readonly byte[] _salt;
        private readonly string _passphrase;
        private readonly PuttyV3Encryption _puttyV3Encryption;

        public SshKeyEncryptionAes256(string passphrase, PuttyV3Encryption? puttyV3Encryption = null)
        {
            _passphrase = passphrase;
            _passPhraseBytes = Encoding.ASCII.GetBytes(passphrase);
            _salt = new byte[SaltLen];
            _puttyV3Encryption = puttyV3Encryption ?? new PuttyV3Encryption();
        }

        public SshKeyEncryptionAes256(string passphrase, Aes256Mode mode, PuttyV3Encryption? puttyV3Encryption = null)
         : this(passphrase, puttyV3Encryption)
        {
            _mode = mode;
        }

        public byte[] KdfOptions()
        {
            using var stream = new MemoryStream();
            using var writer = new BinaryWriter(stream);
            using var rng = new RNGCryptoServiceProvider();
            rng.GetBytes(_salt);
            writer.EncodeBinary(_salt);
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
                    cipher = new AesCipher(key, iv, AesCipherMode.CBC);
                    break;
                default:
                    _mode = Aes256Mode.CTR;
                    cipher = new AesCipher(key, iv, AesCipherMode.CTR);
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

        public byte[] PuttyV2Encrypt(byte[] data)
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
                    cipher = new AesCipher(cipherKey, new byte[cipherKey.Length], AesCipherMode.CBC);
                    break;
            }
            return cipher.Encrypt(data);
        }

        public byte[] PuttyV2Encrypt(byte[] data, int offset, int length)
        {
            var buffer = new byte[length];
            Array.Copy(data, offset, buffer, 0, length);
            return PuttyV2Encrypt(buffer);
        }

        public PuttyV3Encryption PuttyV3Encrypt(byte[] data)
        {
            Argon2 argon2 = _puttyV3Encryption.KeyDerivation switch
            {
                ArgonKeyDerivation.Argon2d  => new Argon2d(_passPhraseBytes),
                ArgonKeyDerivation.Argon2i => new Argon2i(_passPhraseBytes),
                ArgonKeyDerivation.Argon2id => new Argon2id(_passPhraseBytes),
                _ => throw new NotSupportedException($"Encryption Key Derivation {_puttyV3Encryption.KeyDerivation} is not supported.")
            };

            argon2.DegreeOfParallelism = _puttyV3Encryption.DegreeOfParallelism;
            argon2.MemorySize = _puttyV3Encryption.MemorySize;
            argon2.Iterations = _puttyV3Encryption.Iterations;

            using var rng = new RNGCryptoServiceProvider();
            rng.GetBytes(_salt);
            argon2.Salt = _salt;
            _puttyV3Encryption.Salt = _salt;

            var cipherKeyComplete = argon2.GetBytes(80);
            var cipherKey = new byte[32];
            var crcIv = new byte[16];
            var macKey = new byte[32];
            Buffer.BlockCopy(cipherKeyComplete, 0, cipherKey, 0, cipherKey.Length);
            Buffer.BlockCopy(cipherKeyComplete, 32, crcIv, 0, crcIv.Length);
            Buffer.BlockCopy(cipherKeyComplete, 48, macKey, 0, macKey.Length);

            AesCipher cipher;
            switch(_mode)
            {
                case Aes256Mode.CTR:
                    throw new NotSupportedException($"Unsupported AES Mode: {_mode}");
                default:
                    _mode = Aes256Mode.CBC;
                    cipher = new AesCipher(cipherKey, crcIv, AesCipherMode.CBC);
                    break;
            }

            _puttyV3Encryption.Result = cipher.Encrypt(data);
            _puttyV3Encryption.MacKey = macKey;

            return _puttyV3Encryption;
        }

        public PuttyV3Encryption PuttyV3Encrypt(byte[] data, int offset, int length)
        {
            var buffer = new byte[length];
            Array.Copy(data, offset, buffer, 0, length);
            return PuttyV3Encrypt(buffer);
        }
    }
}