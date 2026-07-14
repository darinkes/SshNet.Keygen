namespace SshNet.Keygen.SshKeyEncryption
{
    /// <summary>
    /// Encrypts private key material when a key is exported.
    /// </summary>
    public interface ISshKeyEncryption
    {
        /// <summary>Name of the cipher as written into the key file (for example <c>aes256-ctr</c> or <c>none</c>).</summary>
        public string CipherName { get; }

        /// <summary>Name of the key-derivation function as written into the key file (for example <c>bcrypt</c> or <c>none</c>).</summary>
        public string KdfName { get; }

        /// <summary>Cipher block size, in bytes, used for padding.</summary>
        public int BlockSize { get; }

        /// <summary>The passphrase protecting the key, or an empty string when unencrypted.</summary>
        public string Passphrase { get; }

        /// <summary>Returns the KDF options (salt, rounds, ...) written into the OpenSSH key file.</summary>
        public byte[] KdfOptions();

        /// <summary>Encrypts <paramref name="data"/>.</summary>
        /// <param name="data">The plaintext to encrypt.</param>
        public byte[] Encrypt(byte[] data);

        /// <summary>Encrypts <paramref name="length"/> bytes of <paramref name="data"/> starting at <paramref name="offset"/>.</summary>
        /// <param name="data">The buffer to encrypt from.</param>
        /// <param name="offset">Start offset within <paramref name="data"/>.</param>
        /// <param name="length">Number of bytes to encrypt.</param>
        public byte[] Encrypt(byte[] data, int offset, int length);

        /// <summary>Encrypts <paramref name="data"/> for the PuTTY v2 key format.</summary>
        /// <param name="data">The plaintext to encrypt.</param>
        public byte[] PuttyV2Encrypt(byte[] data);

        /// <summary>Encrypts <paramref name="length"/> bytes of <paramref name="data"/> starting at <paramref name="offset"/> for the PuTTY v2 key format.</summary>
        /// <param name="data">The buffer to encrypt from.</param>
        /// <param name="offset">Start offset within <paramref name="data"/>.</param>
        /// <param name="length">Number of bytes to encrypt.</param>
        public byte[] PuttyV2Encrypt(byte[] data, int offset, int length);

        /// <summary>Encrypts <paramref name="data"/> for the PuTTY v3 key format.</summary>
        /// <param name="data">The plaintext to encrypt.</param>
        public PuttyV3Encryption PuttyV3Encrypt(byte[] data);

        /// <summary>Encrypts <paramref name="length"/> bytes of <paramref name="data"/> starting at <paramref name="offset"/> for the PuTTY v3 key format.</summary>
        /// <param name="data">The buffer to encrypt from.</param>
        /// <param name="offset">Start offset within <paramref name="data"/>.</param>
        /// <param name="length">Number of bytes to encrypt.</param>
        public PuttyV3Encryption PuttyV3Encrypt(byte[] data, int offset, int length);
    }
}
