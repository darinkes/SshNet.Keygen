using System.Collections.Generic;
using Renci.SshNet;
using Renci.SshNet.Security;

namespace SshNet.Keygen
{
    public class PrivateGeneratedKey : IPrivateKeySource
    {
        private readonly List<HostAlgorithm> _hostAlgorithms = new();

        public IReadOnlyCollection<HostAlgorithm> HostKeyAlgorithms => _hostAlgorithms;

        public Key Key { get; }

        public PrivateGeneratedKey(Key key)
        {
            Key = key;
            _hostAlgorithms.Add(new KeyHostAlgorithm(key.ToString(), key));
        }
    }
}