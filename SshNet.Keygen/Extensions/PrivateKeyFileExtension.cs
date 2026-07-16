using System;
using System.Linq;
using System.Security.Cryptography;
using Renci.SshNet;
using Renci.SshNet.Security;
using Renci.SshNet.Security.Cryptography;
using SshNet.Keygen.SshKeyEncryption;

namespace SshNet.Keygen.Extensions
{
    /// <summary>
    /// Export and fingerprint helpers for any SSH.NET <see cref="IPrivateKeySource"/>.
    /// </summary>
    public static class PrivateKeyFileExtension
    {
        #region Fingerprint

        /// <summary>Returns the key fingerprint using the default hash algorithm.</summary>
        /// <param name="keyFile">The key.</param>
        public static string Fingerprint(this IPrivateKeySource keyFile)
        {
            return keyFile.Fingerprint(SshKeyGenerateInfo.DefaultHashAlgorithmName);
        }

        /// <summary>Returns the key fingerprint using the given hash algorithm.</summary>
        /// <param name="keyFile">The key.</param>
        /// <param name="hashAlgorithm">The hash algorithm to use.</param>
        public static string Fingerprint(this IPrivateKeySource keyFile, SshKeyHashAlgorithmName hashAlgorithm)
        {
            return ((KeyHostAlgorithm) keyFile.HostKeyAlgorithms.First()).Key.Fingerprint(hashAlgorithm);
        }

        #endregion

        #region Public

        /// <summary>Returns the public key. For a generated key the source's format is used, otherwise OpenSSH.</summary>
        /// <param name="keyFile">The key.</param>
        public static string ToPublic(this IPrivateKeySource keyFile)
        {
            var keyFormat = SshKeyGenerateInfo.DefaultSshKeyFormat;
            if (keyFile is GeneratedPrivateKey generatedPrivateKey)
                keyFormat = generatedPrivateKey.Info.KeyFormat;

            return keyFile.ToPublic(keyFormat);
        }

        /// <summary>Returns the public key in the given format.</summary>
        /// <param name="keyFile">The key.</param>
        /// <param name="sshKeyFormat">The public key format.</param>
        public static string ToPublic(this IPrivateKeySource keyFile, SshKeyFormat sshKeyFormat)
        {
            return sshKeyFormat is SshKeyFormat.PuTTYv2 or SshKeyFormat.PuTTYv3
                ? keyFile.ToPuttyPublicFormat()
                : ((KeyHostAlgorithm) keyFile.HostKeyAlgorithms.First()).Key.ToPublic();
        }

        /// <summary>Returns the public key in OpenSSH format.</summary>
        /// <param name="keyFile">The key.</param>
        public static string ToOpenSshPublicFormat(this IPrivateKeySource keyFile)
        {
            return keyFile.ToPublic(SshKeyFormat.OpenSSH);
        }

        /// <summary>Returns the public key in PuTTY format.</summary>
        /// <param name="keyFile">The key.</param>
        public static string ToPuttyPublicFormat(this IPrivateKeySource keyFile)
        {
            return ((KeyHostAlgorithm) keyFile.HostKeyAlgorithms.First()).Key.ToPuttyPublicFormat();
        }

        #endregion

        #region OpenSshFormat

        /// <summary>Returns the private key in OpenSSH format. For a generated key the source's encryption is used.</summary>
        /// <param name="keyFile">The key.</param>
        public static string ToOpenSshFormat(this IPrivateKeySource keyFile)
        {
            var encryption = SshKeyGenerateInfo.DefaultSshKeyEncryption;
            if (keyFile is GeneratedPrivateKey generatedPrivateKey)
                encryption = generatedPrivateKey.Info.Encryption;

            return keyFile.ToOpenSshFormat(encryption);
        }

        /// <summary>Returns the private key in OpenSSH format, encrypted with the given passphrase (AES-256).</summary>
        /// <param name="keyFile">The key.</param>
        /// <param name="passphrase">The passphrase to encrypt with.</param>
        public static string ToOpenSshFormat(this IPrivateKeySource keyFile, string passphrase)
        {
            return keyFile.ToOpenSshFormat(new SshKeyEncryptionAes256(passphrase));
        }

        /// <summary>Returns the private key in OpenSSH format using the given encryption.</summary>
        /// <param name="keyFile">The key.</param>
        /// <param name="encryption">The encryption to apply.</param>
        public static string ToOpenSshFormat(this IPrivateKeySource keyFile, ISshKeyEncryption encryption)
        {
            return ((KeyHostAlgorithm) keyFile.HostKeyAlgorithms.First()).Key.ToOpenSshFormat(encryption);
        }

        #endregion

        #region PuttyFormat

        /// <summary>Returns the private key in PuTTY format. For a generated PuTTY key the source's format is used, otherwise PuTTY v3.</summary>
        /// <param name="keyFile">The key.</param>
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

        /// <summary>Returns the private key in PuTTY v3 format, encrypted with the given passphrase (AES-256).</summary>
        /// <param name="keyFile">The key.</param>
        /// <param name="passphrase">The passphrase to encrypt with.</param>
        public static string ToPuttyFormat(this IPrivateKeySource keyFile, string passphrase)
        {
            return keyFile.ToPuttyFormat(new SshKeyEncryptionAes256(passphrase), SshKeyFormat.PuTTYv3);
        }

        /// <summary>Returns the private key in the given PuTTY format, encrypted with the given passphrase (AES-256).</summary>
        /// <param name="keyFile">The key.</param>
        /// <param name="passphrase">The passphrase to encrypt with.</param>
        /// <param name="sshKeyFormat">The PuTTY key format.</param>
        public static string ToPuttyFormat(this IPrivateKeySource keyFile, string passphrase, SshKeyFormat sshKeyFormat)
        {
            return keyFile.ToPuttyFormat(new SshKeyEncryptionAes256(passphrase), sshKeyFormat);
        }

        /// <summary>Returns the private key in the given PuTTY format. For a generated key the source's encryption is used.</summary>
        /// <param name="keyFile">The key.</param>
        /// <param name="sshKeyFormat">The PuTTY key format.</param>
        public static string ToPuttyFormat(this IPrivateKeySource keyFile, SshKeyFormat sshKeyFormat)
        {
            var encryption = SshKeyGenerateInfo.DefaultSshKeyEncryption;
            if (keyFile is GeneratedPrivateKey generatedPrivateKey)
                encryption = generatedPrivateKey.Info.Encryption;

            return keyFile.ToPuttyFormat(encryption, sshKeyFormat);
        }

        /// <summary>Returns the private key in PuTTY v3 format using the given encryption.</summary>
        /// <param name="keyFile">The key.</param>
        /// <param name="encryption">The encryption to apply.</param>
        public static string ToPuttyFormat(this IPrivateKeySource keyFile, ISshKeyEncryption encryption)
        {
            return keyFile.ToPuttyFormat(encryption, SshKeyFormat.PuTTYv3);
        }

        /// <summary>Returns the private key in the given PuTTY format using the given encryption.</summary>
        /// <param name="keyFile">The key.</param>
        /// <param name="encryption">The encryption to apply.</param>
        /// <param name="sshKeyFormat">The PuTTY key format.</param>
        public static string ToPuttyFormat(this IPrivateKeySource keyFile, ISshKeyEncryption encryption, SshKeyFormat sshKeyFormat)
        {
            return ((KeyHostAlgorithm) keyFile.HostKeyAlgorithms.First()).Key.ToPuttyFormat(encryption, sshKeyFormat);
        }

        #endregion

        #region Sign

        /// <summary>Signs <paramref name="data"/> with the key and returns an armored SSHSIG signature.</summary>
        /// <param name="keyFile">The signing key.</param>
        /// <param name="data">The data to sign.</param>
        /// <param name="namespace">The SSHSIG namespace the signature is bound to (OpenSSH uses e.g. <c>file</c> or <c>git</c>).</param>
        public static string Signature(this IPrivateKeySource keyFile, byte[] data, string @namespace = "file")
        {
            return GetSignKeyHostAlgorithm(keyFile).Signature(data, @namespace);
        }

        /// <summary>Signs the file at <paramref name="path"/>, writing the signature to <c>&lt;path&gt;.sig</c>.</summary>
        /// <param name="keyFile">The signing key.</param>
        /// <param name="path">The file to sign.</param>
        /// <param name="namespace">The SSHSIG namespace the signature is bound to (OpenSSH uses e.g. <c>file</c> or <c>git</c>).</param>
        public static void SignatureFile(this IPrivateKeySource keyFile, string path, string @namespace = "file")
        {
            GetSignKeyHostAlgorithm(keyFile).SignatureFile(path, @namespace);
        }

        private static KeyHostAlgorithm GetSignKeyHostAlgorithm(this IPrivateKeySource keyFile)
        {
            var keyHostAlgorithm = (KeyHostAlgorithm)keyFile.HostKeyAlgorithms.First();
            if (keyHostAlgorithm.Key is RsaKey rsaKey)
            {
                keyHostAlgorithm = new KeyHostAlgorithm("rsa-sha2-512", keyHostAlgorithm.Key, new RsaDigitalSignature(rsaKey, HashAlgorithmName.SHA512));
            }

            return keyHostAlgorithm;
        }


        #endregion
    }
}
