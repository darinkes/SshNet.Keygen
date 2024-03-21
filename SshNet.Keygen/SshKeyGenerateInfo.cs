using System;
using System.Security.Cryptography;
using SshNet.Keygen.SshKeyEncryption;

namespace SshNet.Keygen
{
    public class SshKeyGenerateInfo
    {
        public const SshKeyHashAlgorithmName DefaultHashAlgorithmName = SshKeyHashAlgorithmName.SHA256;

        public static readonly ISshKeyEncryption DefaultSshKeyEncryption = new SshKeyEncryptionNone();

        public static readonly string DefaultSshKeyComment = $"{Environment.UserName}@{Environment.MachineName}";

        public const SshKeyFormat DefaultSshKeyFormat = SshKeyFormat.OpenSSH;

        public const SshKeyType DefaultSshKeyType = SshKeyType.RSA;

        public const int DefaultEcdsaSshKeyLength = 256;

        public const int DefaultEd25519SshKeyLength = 256;

        public const int DefaultRsaSshKeyLength = 2048;

        public ISshKeyEncryption Encryption { get; set; }

        public string Comment { get; set; }

        public SshKeyFormat KeyFormat { get; set; }

        public int KeyLength { get; set; }

        public SshKeyType KeyType { get; set; }

        public RSA? Rsa { get; set; }

#if NETSTANDARD
        public ECDsa? Ecdsa { get; set; }
#else
        public ECDsaCng? Ecdsa { get; set; }
#endif

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