using System.Security.Cryptography;
using Renci.SshNet.Security;

namespace SshNet.Keygen.Extensions
{
    public static class KeyHostAlgorithmExtension
    {
        #region Sign

        internal static string Signature(this KeyHostAlgorithm keyHostAlgorithm, byte[] data)
        {
            return SshSignature.Signature(keyHostAlgorithm, data);
        }

        internal static void SignatureFile(this KeyHostAlgorithm keyHostAlgorithm, string path)
        {
            SshSignature.SignatureFile(keyHostAlgorithm, path);
        }

        #endregion
    }
}