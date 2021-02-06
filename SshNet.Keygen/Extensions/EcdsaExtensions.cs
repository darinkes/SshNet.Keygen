using System.Security.Cryptography;

namespace SshNet.Keygen.Extensions
{
    internal static class EcdsaExtensions
    {
        // XXX: EcParameters.Curve.Oid.FriendlyName returns with a P instead of p
        public static string EcCurveNameSshCompat(this ECDsa ecdsa)
        {
            return ecdsa.KeySize switch
            {
                256 => "nistp256",
                384 => "nistp384",
                521 => "nistp521",
                _ => throw new CryptographicException("Unsupported KeyLength")
            };
        }
    }
}