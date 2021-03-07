using System;
using System.Security.Cryptography;

namespace SshNet.Keygen.Extensions
{
    internal static class EcdsaExtension
    {
        private static byte[] UncompressedCoords(byte[] qx, byte[] qy)
        {
            var q = new byte[1 + qx.Length + qy.Length];
            Buffer.SetByte(q, 0, 4);
            Buffer.BlockCopy(qx, 0, q, 1, qx.Length);
            Buffer.BlockCopy(qy, 0, q, qx.Length + 1, qy.Length);
            return q;
        }

#if NETSTANDARD
        // EcParameters.Curve.Oid.FriendlyName returns different values if OpenSSL or Windows-Crypto
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

        public static byte[] UncompressedCoords(this ECParameters ecdsaParameters)
        {
            var qx = ecdsaParameters.Q.X;
            var qy = ecdsaParameters.Q.Y;
            return UncompressedCoords(qx, qy);
        }
#else
        public enum KeyBlobMagicNumber
        {
            BCRYPT_ECDSA_PRIVATE_P256_MAGIC = 0x32534345,
            BCRYPT_ECDSA_PRIVATE_P384_MAGIC = 0x34534345,
            BCRYPT_ECDSA_PRIVATE_P521_MAGIC = 0x36534345
        }

        public static string EcCurveNameSshCompat(this ECDsaCng ecdsa, KeyBlobMagicNumber magic)
        {
            return magic switch
            {
                KeyBlobMagicNumber.BCRYPT_ECDSA_PRIVATE_P256_MAGIC => "nistp256",
                KeyBlobMagicNumber.BCRYPT_ECDSA_PRIVATE_P384_MAGIC => "nistp384",
                KeyBlobMagicNumber.BCRYPT_ECDSA_PRIVATE_P521_MAGIC => "nistp521",
                _ => throw new CryptographicException("Unexpected Curve Magic: {magic}")
            };
        }

        public static byte[] UncompressedCoords(this ECDsaCng ecdsa, byte[] qx, byte[] qy)
        {
            return UncompressedCoords(qx, qy);
        }
#endif
    }
}
