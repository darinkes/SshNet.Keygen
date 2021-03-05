using System;
using System.Security.Cryptography;

namespace SshNet.Keygen.Extensions
{
    internal static class EcdsaExtension
    {
        // EcParameters.Curve.Oid.FriendlyName returns with a P instead of p
#if NET40
        public static string EcCurveNameSshCompat(this ECDsaCng ecdsa)
#else
        public static string EcCurveNameSshCompat(this ECDsa ecdsa)
#endif
        {
            return ecdsa.KeySize switch
            {
                256 => "nistp256",
                384 => "nistp384",
                521 => "nistp521",
                _ => throw new CryptographicException("Unsupported KeyLength")
            };
        }

#if NET40
        public static int EcCoordsLength(this ECDsaCng ecdsa)
#else
        public static int EcCoordsLength(this ECDsa ecdsa)
#endif
        {
            return ecdsa.KeySize switch
            {
                256 => 32,
                384 => 48,
                521 => 66,
                _ => throw new CryptographicException("Unsupported KeyLength")
            };
        }

#if NETSTANDARD
        public static byte[] UncompressedCoords(this ECParameters ecdsaParameters, int coordLength)
        {
            return UncompressedCoords(ecdsaParameters.Q.X, ecdsaParameters.Q.Y, coordLength);
        }
#endif

        public static byte[] UncompressedCoords(byte[] qx, byte[] qy, int coordLength)
        {
            var q = new byte[1 + 2 * coordLength];
            Buffer.SetByte(q, 0, 4); // Uncompressed
            Buffer.BlockCopy(qx.Pad(coordLength), 0, q, 1, coordLength);
            Buffer.BlockCopy(qy.Pad(coordLength), 0, q, coordLength + 1, coordLength);
            return q;
        }
    }
}
