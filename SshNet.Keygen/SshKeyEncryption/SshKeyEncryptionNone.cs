using System;

namespace SshNet.Keygen.SshKeyEncryption
{
    /// <summary>
    /// No-op encryption: exports the key unencrypted.
    /// </summary>
    public class SshKeyEncryptionNone : ISshKeyEncryption
    {
        /// <inheritdoc />
        public string CipherName => "none";
        /// <inheritdoc />
        public string KdfName => "none";
        /// <inheritdoc />
        public int BlockSize => 8;
        /// <inheritdoc />
        public string Passphrase => "";

        /// <inheritdoc />
        public byte[] KdfOptions()
        {
            return new byte[] { };
        }

        /// <inheritdoc />
        public byte[] Encrypt(byte[] data)
        {
            return data;
        }

        /// <inheritdoc />
        public byte[] Encrypt(byte[] data, int offset, int length)
        {
            var buffer = new byte[length];
            Buffer.BlockCopy(data, offset, buffer, 0, length);
            return Encrypt(buffer);
        }

        /// <inheritdoc />
        public byte[] PuttyV2Encrypt(byte[] data)
        {
            return Encrypt(data);
        }

        /// <inheritdoc />
        public byte[] PuttyV2Encrypt(byte[] data, int offset, int length)
        {
            return Encrypt(data, offset, length);
        }

        /// <inheritdoc />
        public PuttyV3Encryption PuttyV3Encrypt(byte[] data)
        {
            return new PuttyV3Encryption { Result = Encrypt(data) };
        }

        /// <inheritdoc />
        public PuttyV3Encryption PuttyV3Encrypt(byte[] data, int offset, int length)
        {
            return new PuttyV3Encryption { Result = Encrypt(data, offset, length) };
        }
    }
}
