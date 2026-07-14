using System.Collections.Generic;
using System.Security.Cryptography;
using Renci.SshNet;
using Renci.SshNet.Security;
using Renci.SshNet.Security.Cryptography;

namespace SshNet.Keygen
{
    /// <summary>
    /// A freshly generated key, usable directly as an SSH.NET <see cref="IPrivateKeySource"/>.
    /// </summary>
    public class GeneratedPrivateKey : IPrivateKeySource
    {
        private readonly List<HostAlgorithm> _hostAlgorithms = new();

        /// <summary>The host key algorithms this key supports.</summary>
        public IReadOnlyCollection<HostAlgorithm> HostKeyAlgorithms => _hostAlgorithms;

        /// <summary>The generated key.</summary>
        public Key Key { get; }

        /// <summary>The options the key was generated with.</summary>
        public SshKeyGenerateInfo Info { get; }

        /// <summary>Wraps a generated <paramref name="key"/> together with the <paramref name="info"/> it was created from.</summary>
        /// <param name="key">The generated key.</param>
        /// <param name="info">The options the key was generated with.</param>
        public GeneratedPrivateKey(Key key, SshKeyGenerateInfo info)
        {
            Key = key;
            Info = info;

            _hostAlgorithms.Add(new KeyHostAlgorithm(key.ToString(), key));

            if (Key is not RsaKey rsaKey)
                return;
            _hostAlgorithms.Add(new KeyHostAlgorithm("rsa-sha2-512", key, new RsaDigitalSignature(rsaKey, HashAlgorithmName.SHA512)));
            _hostAlgorithms.Add(new KeyHostAlgorithm("rsa-sha2-256", key, new RsaDigitalSignature(rsaKey, HashAlgorithmName.SHA256)));
        }
    }
}
