﻿using Renci.SshNet;
using Renci.SshNet.Security;
using SshNet.Keygen.SshKeyEncryption;

namespace SshNet.Keygen.Extensions
{
    public static class PrivateKeyFileExtension
    {
        #region Fingerprint

        public static string Fingerprint(this IPrivateKeyFile keyFile)
        {
            return keyFile.Fingerprint(SshKeyGenerateInfo.DefaultHashAlgorithmName);
        }

        public static string Fingerprint(this IPrivateKeyFile keyFile, SshKeyHashAlgorithmName hashAlgorithm)
        {
            return ((KeyHostAlgorithm) keyFile.HostKey).Key.Fingerprint(hashAlgorithm);
        }

        #endregion

        #region Public

        public static string ToPublic(this IPrivateKeyFile keyFile)
        {
            return ((KeyHostAlgorithm) keyFile.HostKey).Key.ToPublic();
        }

        #endregion

        #region OpenSshFormat

        public static string ToOpenSshFormat(this IPrivateKeyFile keyFile)
        {
            return ((KeyHostAlgorithm) keyFile.HostKey).Key.ToOpenSshFormat(SshKeyGenerateInfo.DefaultSshKeyEncryption);
        }

        public static string ToOpenSshFormat(this IPrivateKeyFile keyFile, ISshKeyEncryption encryption)
        {
            return ((KeyHostAlgorithm) keyFile.HostKey).Key.ToOpenSshFormat(encryption);
        }

        #endregion

        #region PuttyFormat

        public static string ToPuttyFormat(this IPrivateKeyFile keyFile)
        {
            return ((KeyHostAlgorithm) keyFile.HostKey).Key.ToPuttyFormat(SshKeyGenerateInfo.DefaultSshKeyEncryption);
        }

        public static string ToPuttyFormat(this IPrivateKeyFile keyFile, ISshKeyEncryption encryption)
        {
            return ((KeyHostAlgorithm) keyFile.HostKey).Key.ToPuttyFormat(encryption);
        }

        #endregion
    }
}