using System;
using System.Security.Cryptography;

namespace SshNet.Keygen.SshKeyEncryption
{
    public enum SshKeyHashAlgorithmName
    {
        MD5,
        SHA1,
        SHA256,
        SHA384,
        SHA512
    }

    internal static class SshKeyHashAlgorithm
    {
        public static string HashAlgorithmName(SshKeyHashAlgorithmName algorithmName)
        {
            return algorithmName switch
            {
                SshKeyHashAlgorithmName.MD5 => "MD5",
                SshKeyHashAlgorithmName.SHA1 => "SHA1",
                SshKeyHashAlgorithmName.SHA256 => "SHA256",
                SshKeyHashAlgorithmName.SHA384 => "SHA384",
                SshKeyHashAlgorithmName.SHA512 => "SHA512",
                _ => throw new NotSupportedException($"Unknown Algorithm: {algorithmName}")
            };
        }

        public static HashAlgorithm Create(SshKeyHashAlgorithmName algorithmName)
        {
            return algorithmName switch
            {
                SshKeyHashAlgorithmName.MD5 => CreateMD5(),
                SshKeyHashAlgorithmName.SHA1 => CreateSHA1(),
                SshKeyHashAlgorithmName.SHA256 => CreateSHA256(),
                SshKeyHashAlgorithmName.SHA384 => CreateSHA384(),
                SshKeyHashAlgorithmName.SHA512 => CreateSHA512(),
                _ => throw new NotSupportedException($"Unknown Algorithm: {algorithmName}")
            };
        }

        private static MD5 CreateMD5()
        {
            return MD5.Create();
        }

        private static SHA1 CreateSHA1()
        {
#if NET40
            return new SHA1Managed();
#else
            return SHA1.Create();
#endif
        }

        private static SHA256 CreateSHA256()
        {
#if NET40
            return new SHA256Managed();
#else
            return SHA256.Create();
#endif
        }

        private static SHA384 CreateSHA384()
        {
#if NET40
            return new SHA384Managed();
#else
            return SHA384.Create();
#endif
        }

        private static SHA512 CreateSHA512()
        {
#if NET40
            return new SHA512Managed();
#else
            return SHA512.Create();
#endif
        }
    }
}