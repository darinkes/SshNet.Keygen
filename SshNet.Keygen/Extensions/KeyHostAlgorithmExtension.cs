using System.Security.Cryptography;
using Renci.SshNet.Security;

namespace SshNet.Keygen.Extensions
{
    internal static class KeyHostAlgorithmExtension
    {
        #region Sign

        internal static string Signature(this KeyHostAlgorithm keyHostAlgorithm, byte[] data, string @namespace = "file")
        {
            return SshSignature.Signature(keyHostAlgorithm, data, @namespace);
        }

        internal static void SignatureFile(this KeyHostAlgorithm keyHostAlgorithm, string path, string @namespace = "file")
        {
            SshSignature.SignatureFile(keyHostAlgorithm, path, @namespace);
        }

        #endregion
    }
}