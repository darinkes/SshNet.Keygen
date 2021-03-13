using Renci.SshNet;
using Renci.SshNet.Security;
using SshNet.Keygen.SshKeyEncryption;

namespace SshNet.Keygen.Extensions
{
    public static class PrivateKeyFileExtension
    {
        #region Fingerprint

        public static string Fingerprint(this PrivateKeyFile keyFile)
        {
            return keyFile.Fingerprint(SshKey.DefaultHashAlgorithmName);
        }

        public static string Fingerprint(this PrivateKeyFile keyFile, SshKeyHashAlgorithmName hashAlgorithm)
        {
            return ((KeyHostAlgorithm) keyFile.HostKey).Key.Fingerprint(hashAlgorithm);
        }

        #endregion

        #region Public

        public static string ToPublic(this PrivateKeyFile keyFile)
        {
            return ((KeyHostAlgorithm) keyFile.HostKey).Key.ToPublic();
        }

        #endregion

        #region OpenSshFormat

        public static string ToOpenSshFormat(this PrivateKeyFile keyFile)
        {
            return ((KeyHostAlgorithm) keyFile.HostKey).Key.ToOpenSshFormat(SshKey.DefaultSshKeyEncryption);
        }

        public static string ToOpenSshFormat(this PrivateKeyFile keyFile, ISshKeyEncryption encryption)
        {
            return ((KeyHostAlgorithm) keyFile.HostKey).Key.ToOpenSshFormat(encryption);
        }

        #endregion

        #region PuttyFormat

        public static string ToPuttyFormat(this PrivateKeyFile keyFile)
        {
            return ((KeyHostAlgorithm) keyFile.HostKey).Key.ToPuttyFormat(SshKey.DefaultSshKeyEncryption);
        }

        public static string ToPuttyFormat(this PrivateKeyFile keyFile, ISshKeyEncryption encryption)
        {
            return ((KeyHostAlgorithm) keyFile.HostKey).Key.ToPuttyFormat(encryption);
        }

        #endregion
    }
}