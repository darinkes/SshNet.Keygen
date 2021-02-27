using System;
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
        Cbc,
        Ctr,
    }

    public class SshKeyEncryptionAes256 : ISshKeyEncryption
    {
        public string CipherName => $"aes256-{_mode.ToString().ToLower()}";
        public string KdfName => "bcrypt";
        public int BlockSize => 16;

        private const int SaltLen = 16;
        private const int Rounds = 16;
        private readonly Aes256Mode _mode;
        private readonly byte[] _passPhraseBytes;
        private readonly byte[] _salt;

        public SshKeyEncryptionAes256(string passphrase, Aes256Mode mode = Aes256Mode.Ctr)
        {
            _mode = mode;
            _passPhraseBytes = Encoding.ASCII.GetBytes(passphrase);
            _salt = new byte[SaltLen];
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

            var cipher = _mode switch
            {
                Aes256Mode.Cbc => new AesCipher(key, new CbcCipherMode(iv), new PKCS7Padding()),
                Aes256Mode.Ctr => new AesCipher(key, new CtrCipherMode(iv), new PKCS7Padding()),
                _ => throw new CryptographicException("Unsupported AES Mode")
            };
            return cipher.Encrypt(data);
        }

        public byte[] Encrypt(byte[] data, int offset, int length)
        {
            var buffer = new byte[length];
            Array.Copy(data, offset, buffer, 0, length);
            return Encrypt(buffer);
        }
    }
}