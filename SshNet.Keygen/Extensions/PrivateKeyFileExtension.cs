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
            var keyFormat = SshKeyGenerateInfo.DefaultSshKeyFormat;
            if (keyFile is GeneratedPrivateKey generatedPrivateKey)
                keyFormat = generatedPrivateKey.Info.KeyFormat;

            return keyFile.ToPublic(keyFormat);
        }

        public static string ToPublic(this IPrivateKeySource keyFile, SshKeyFormat sshKeyFormat)
        {
            return sshKeyFormat is SshKeyFormat.PuTTYv2 or SshKeyFormat.PuTTYv3
                ? keyFile.ToPuttyPublicFormat()
                : ((KeyHostAlgorithm) keyFile.HostKeyAlgorithms.First()).Key.ToPublic();
        }

        public static string ToOpenSshPublicFormat(this IPrivateKeySource keyFile)
        {
            return keyFile.ToPublic(SshKeyFormat.OpenSSH);
        }

        public static string ToPuttyPublicFormat(this IPrivateKeySource keyFile)
        {
            return ((KeyHostAlgorithm) keyFile.HostKeyAlgorithms.First()).Key.ToPuttyPublicFormat();
        }

        #endregion

        #region OpenSshFormat

        public static string ToOpenSshFormat(this IPrivateKeySource keyFile)
        {
            var encryption = SshKeyGenerateInfo.DefaultSshKeyEncryption;
            if (keyFile is GeneratedPrivateKey generatedPrivateKey)
                encryption = generatedPrivateKey.Info.Encryption;

            return keyFile.ToOpenSshFormat(encryption);
        }

        public static string ToOpenSshFormat(this IPrivateKeySource keyFile, string passphrase)
        {
            return keyFile.ToOpenSshFormat(new SshKeyEncryptionAes256(passphrase));
        }

        public static string ToOpenSshFormat(this IPrivateKeySource keyFile, ISshKeyEncryption encryption)
        {
            return ((KeyHostAlgorithm) keyFile.HostKeyAlgorithms.First()).Key.ToOpenSshFormat(encryption);
        }

        #endregion

        #region PuttyFormat

        public static string ToPuttyFormat(this IPrivateKeySource keyFile)
        {
            var sshKeyFormat = SshKeyFormat.PuTTYv3;
            if (keyFile is GeneratedPrivateKey generatedPrivateKey)
            {
                if (generatedPrivateKey.Info.KeyFormat is SshKeyFormat.PuTTYv2 or SshKeyFormat.PuTTYv3)
                    sshKeyFormat = generatedPrivateKey.Info.KeyFormat;
            }

            return keyFile.ToPuttyFormat(sshKeyFormat);
        }

        public static string ToPuttyFormat(this IPrivateKeySource keyFile, string passphrase)
        {
            return keyFile.ToPuttyFormat(new SshKeyEncryptionAes256(passphrase), SshKeyFormat.PuTTYv3);
        }

        public static string ToPuttyFormat(this IPrivateKeySource keyFile, string passphrase, SshKeyFormat sshKeyFormat)
        {
            return keyFile.ToPuttyFormat(new SshKeyEncryptionAes256(passphrase), sshKeyFormat);
        }

        public static string ToPuttyFormat(this IPrivateKeySource keyFile, SshKeyFormat sshKeyFormat)
        {
            var encryption = SshKeyGenerateInfo.DefaultSshKeyEncryption;
            if (keyFile is GeneratedPrivateKey generatedPrivateKey)
                encryption = generatedPrivateKey.Info.Encryption;

            return keyFile.ToPuttyFormat(encryption, sshKeyFormat);
        }

        public static string ToPuttyFormat(this IPrivateKeySource keyFile, ISshKeyEncryption encryption)
        {
            return keyFile.ToPuttyFormat(encryption, SshKeyFormat.PuTTYv3);
        }

        public static string ToPuttyFormat(this IPrivateKeySource keyFile, ISshKeyEncryption encryption, SshKeyFormat sshKeyFormat)
        {
            return ((KeyHostAlgorithm) keyFile.HostKeyAlgorithms.First()).Key.ToPuttyFormat(encryption, sshKeyFormat);
        }

        #endregion
    }
}