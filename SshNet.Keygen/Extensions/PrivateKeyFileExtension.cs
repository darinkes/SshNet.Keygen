using Renci.SshNet;
using Renci.SshNet.Security;
using SshNet.Keygen.SshKeyEncryption;

namespace SshNet.Keygen.Extensions
{
    public static class PrivateKeyFileExtension
    {
        public static string Fingerprint(this PrivateKeyFile keyFile)
        {
            return keyFile.Fingerprint(SshKey.DefaultHashAlgorithmName);
        }

        public static string Fingerprint(this PrivateKeyFile keyFile, SshKeyHashAlgorithmName hashAlgorithm)
        {
            return ((KeyHostAlgorithm) keyFile.HostKey).Key.Fingerprint(hashAlgorithm);
        }

        public static string ToOpenSshFormat(this PrivateKeyFile keyFile)
        {
            return ((KeyHostAlgorithm) keyFile.HostKey).Key.ToOpenSshFormat(SshKey.DefaultSshKeyEncryption);
        }

        public static string ToOpenSshFormat(this PrivateKeyFile keyFile, ISshKeyEncryption encryption)
        {
            return ((KeyHostAlgorithm) keyFile.HostKey).Key.ToOpenSshFormat(encryption);
        }

        public static string ToOpenSshPublicFormat(this PrivateKeyFile keyFile)
        {
            return ((KeyHostAlgorithm) keyFile.HostKey).Key.ToOpenSshPublicFormat();
        }
    }
}