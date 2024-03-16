using System.Linq;
using Renci.SshNet;
using Renci.SshNet.Security;
using SshNet.Keygen.SshKeyEncryption;

namespace SshNet.Keygen.Extensions
{
    public static class PrivateKeyFileExtension
    {
        #region Fingerprint

        public static string Fingerprint(this IPrivateKeySource keyFile)
        {
            return keyFile.Fingerprint(SshKeyGenerateInfo.DefaultHashAlgorithmName);
        }

        public static string Fingerprint(this IPrivateKeySource keyFile, SshKeyHashAlgorithmName hashAlgorithm)
        {
            return ((KeyHostAlgorithm) keyFile.HostKeyAlgorithms.First()).Key.Fingerprint(hashAlgorithm);
        }

        #endregion

        #region Public

        public static string ToPublic(this IPrivateKeySource keyFile)
        {
            return ((KeyHostAlgorithm) keyFile.HostKeyAlgorithms.First()).Key.ToPublic();
        }

        #endregion

        #region OpenSshFormat

        public static string ToOpenSshFormat(this IPrivateKeySource keyFile)
        {
            var encryption = SshKeyGenerateInfo.DefaultSshKeyEncryption;
            if (keyFile is GeneratedPrivateKey generatedPrivateKey)
                encryption = generatedPrivateKey.Info.Encryption;

            return ((KeyHostAlgorithm) keyFile.HostKeyAlgorithms.First()).Key.ToOpenSshFormat(encryption);
        }

        public static string ToOpenSshFormat(this IPrivateKeySource keyFile, ISshKeyEncryption encryption)
        {
            return ((KeyHostAlgorithm) keyFile.HostKeyAlgorithms.First()).Key.ToOpenSshFormat(encryption);
        }

        #endregion

        #region PuttyFormat

        public static string ToPuttyFormat(this IPrivateKeySource keyFile)
        {
            var encryption = SshKeyGenerateInfo.DefaultSshKeyEncryption;
            if (keyFile is GeneratedPrivateKey generatedPrivateKey)
                encryption = generatedPrivateKey.Info.Encryption;

            return ((KeyHostAlgorithm) keyFile.HostKeyAlgorithms.First()).Key.ToPuttyFormat(encryption);
        }

        public static string ToPuttyFormat(this IPrivateKeySource keyFile, ISshKeyEncryption encryption)
        {
            return ((KeyHostAlgorithm) keyFile.HostKeyAlgorithms.First()).Key.ToPuttyFormat(encryption);
        }

        #endregion
    }
}