using System.Collections.Generic;
using System.Security.Cryptography;
using Renci.SshNet;
using Renci.SshNet.Security;
using Renci.SshNet.Security.Cryptography;

namespace SshNet.Keygen
{
    public class GeneratedPrivateKey : IPrivateKeySource
    {
        private readonly List<HostAlgorithm> _hostAlgorithms = new();

        public IReadOnlyCollection<HostAlgorithm> HostKeyAlgorithms => _hostAlgorithms;

        public Key Key { get; }

        public SshKeyGenerateInfo Info { get; }

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