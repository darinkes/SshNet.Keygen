using Renci.SshNet;
using Renci.SshNet.Security;

namespace SshNet.Keygen
{
    public class PrivateGeneratedKey : IPrivateKeyFile
    {
        public HostAlgorithm HostKey { get; }

        public PrivateGeneratedKey(Key key)
        {
            HostKey = new KeyHostAlgorithm(key.ToString(), key);
        }
    }
}