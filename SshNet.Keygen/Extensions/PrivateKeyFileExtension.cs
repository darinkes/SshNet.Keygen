using Renci.SshNet;
using Renci.SshNet.Security;
using SshNet.Keygen.SshKeyEncryption;

namespace SshNet.Keygen.Extensions
{
    public static class PrivateKeyFileExtension
    {
        public static string Fingerprint(this PrivateKeyFile keyFile, string comment = "")
        {
            return keyFile.Fingerprint(SshKey.DefaultHashAlgorithmName, comment);
        }

        public static string Fingerprint(this PrivateKeyFile keyFile, SshKeyHashAlgorithmName hashAlgorithm,  string comment = "")
        {
            return ((KeyHostAlgorithm) keyFile.HostKey).Key.Fingerprint(hashAlgorithm, comment);
        }

        public static string ToOpenSshFormat(this PrivateKeyFile keyFile, string comment = "")
        {
            return ((KeyHostAlgorithm) keyFile.HostKey).Key.ToOpenSshFormat(SshKey.DefaultSshKeyEncryption, comment);
        }

        public static string ToOpenSshFormat(this PrivateKeyFile keyFile, ISshKeyEncryption encryption, string comment = "")
        {
            return ((KeyHostAlgorithm) keyFile.HostKey).Key.ToOpenSshFormat(encryption, comment);
        }

        public static string ToOpenSshPublicFormat(this PrivateKeyFile keyFile, string comment = "")
        {
            return ((KeyHostAlgorithm) keyFile.HostKey).Key.ToOpenSshPublicFormat(comment);
        }
    }
}