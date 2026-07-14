using System;
using SshNet.Keygen.SshKeyEncryption;

namespace SshNet.Keygen
{
    /// <summary>
    /// Options controlling how a key is generated and exported.
    /// </summary>
    public class SshKeyGenerateInfo
    {
        /// <summary>Default fingerprint hash algorithm (<see cref="SshKeyHashAlgorithmName.SHA256"/>).</summary>
        public const SshKeyHashAlgorithmName DefaultHashAlgorithmName = SshKeyHashAlgorithmName.SHA256;

        /// <summary>Default encryption (none — the key is exported unencrypted).</summary>
        public static readonly ISshKeyEncryption DefaultSshKeyEncryption = new SshKeyEncryptionNone();

        /// <summary>Default key comment (<c>user@machine</c>).</summary>
        public static readonly string DefaultSshKeyComment = $"{Environment.UserName}@{Environment.MachineName}";

        /// <summary>Default key format (<see cref="SshKeyFormat.OpenSSH"/>).</summary>
        public const SshKeyFormat DefaultSshKeyFormat = SshKeyFormat.OpenSSH;

        /// <summary>Default key type (<see cref="SshKeyType.RSA"/>).</summary>
        public const SshKeyType DefaultSshKeyType = SshKeyType.RSA;

        /// <summary>Default ECDSA key length, in bits.</summary>
        public const int DefaultEcdsaSshKeyLength = 256;

        /// <summary>Default Ed25519 key length, in bits.</summary>
        public const int DefaultEd25519SshKeyLength = 256;

        /// <summary>Default RSA key length, in bits.</summary>
        public const int DefaultRsaSshKeyLength = 2048;

        /// <summary>Encryption applied when the key is exported.</summary>
        public ISshKeyEncryption Encryption { get; set; }

        /// <summary>Comment stored with the key.</summary>
        public string Comment { get; set; }

        /// <summary>Format the key is exported in.</summary>
        public SshKeyFormat KeyFormat { get; set; }

        /// <summary>Key length in bits. Ignored for Ed25519.</summary>
        public int KeyLength { get; set; }

        /// <summary>The key algorithm to generate.</summary>
        public SshKeyType KeyType { get; set; }

        /// <summary>
        /// Initializes generation options for the given key type, applying the matching default key length.
        /// </summary>
        /// <param name="keyType">The key algorithm to generate.</param>
        public SshKeyGenerateInfo(SshKeyType keyType = DefaultSshKeyType)
        {
            Encryption = DefaultSshKeyEncryption;
            Comment = DefaultSshKeyComment;
            KeyFormat = DefaultSshKeyFormat;
            KeyType = keyType;
            switch (KeyType)
            {
                case SshKeyType.RSA:
                    KeyLength = DefaultRsaSshKeyLength;
                    break;
                case SshKeyType.ECDSA:
                    KeyLength = DefaultEcdsaSshKeyLength;
                    break;
                case SshKeyType.ED25519:
                    KeyLength = DefaultEd25519SshKeyLength;
                    break;
            }
        }
    }
}
