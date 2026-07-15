using System.IO;
using SshNet.Keygen.SshKeyEncryption;

namespace SshNet.Keygen
{
    /// <summary>
    /// Fluent builder for generating SSH keys. Accumulates options, then call a
    /// <c>Generate</c> overload to produce the key.
    /// </summary>
    public class SshKeyBuilder
    {
        private readonly SshKeyGenerateInfo _info;

        /// <summary>Starts a builder for the given key type, using that type's default key length.</summary>
        /// <param name="keyType">The key algorithm to generate.</param>
        public SshKeyBuilder(SshKeyType keyType = SshKeyGenerateInfo.DefaultSshKeyType)
        {
            _info = new SshKeyGenerateInfo(keyType);
        }

        /// <summary>Sets the key algorithm and resets the key length to that type's default.</summary>
        /// <param name="keyType">The key algorithm to generate.</param>
        public SshKeyBuilder OfType(SshKeyType keyType)
        {
            _info.KeyType = keyType;
            _info.KeyLength = SshKeyGenerateInfo.DefaultKeyLength(keyType);
            return this;
        }

        /// <summary>Sets the key length in bits. Ignored for Ed25519.</summary>
        /// <param name="bits">Key length in bits.</param>
        public SshKeyBuilder WithKeyLength(int bits)
        {
            _info.KeyLength = bits;
            return this;
        }

        /// <summary>Sets the comment stored with the key.</summary>
        /// <param name="comment">The comment.</param>
        public SshKeyBuilder WithComment(string comment)
        {
            _info.Comment = comment;
            return this;
        }

        /// <summary>Sets the format the key is exported in.</summary>
        /// <param name="format">The export format.</param>
        public SshKeyBuilder WithFormat(SshKeyFormat format)
        {
            _info.KeyFormat = format;
            return this;
        }

        /// <summary>Sets the encryption applied when the key is exported.</summary>
        /// <param name="encryption">The encryption.</param>
        public SshKeyBuilder WithEncryption(ISshKeyEncryption encryption)
        {
            _info.Encryption = encryption;
            return this;
        }

        /// <summary>Protects the key with a passphrase (AES-256).</summary>
        /// <param name="passphrase">The passphrase.</param>
        public SshKeyBuilder WithPassphrase(string passphrase)
        {
            _info.Encryption = new SshKeyEncryptionAes256(passphrase);
            return this;
        }

        /// <summary>Generates the key in memory.</summary>
        public GeneratedPrivateKey Generate()
        {
            return SshKey.Generate(_info);
        }

        /// <summary>Generates the key and writes it to <paramref name="stream"/>.</summary>
        /// <param name="stream">Destination stream.</param>
        public GeneratedPrivateKey Generate(Stream stream)
        {
            return SshKey.Generate(stream, _info);
        }

        /// <summary>Generates the key and writes it to <paramref name="path"/>.</summary>
        /// <param name="path">Destination file path.</param>
        /// <param name="mode">How the destination file is opened.</param>
        public GeneratedPrivateKey Generate(string path, FileMode mode = FileMode.Create)
        {
            return SshKey.Generate(path, mode, _info);
        }
    }
}
