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

        // EcParameters.Curve.Oid.FriendlyName returns different values if OpenSSL or Windows-Crypto, so match on the OID value
        public static string EcCurveNameSshCompat(this ECDsa ecdsa)
        {
            var oid = ecdsa.ExportParameters(false).Curve.Oid;
            return oid?.Value switch
            {
                "1.2.840.10045.3.1.7" => "nistp256",
                "1.3.132.0.34" => "nistp384",
                "1.3.132.0.35" => "nistp521",
                // some platforms report no OID value; fall back to the key size
                null or "" => ecdsa.KeySize switch
                {
                    256 => "nistp256",
                    384 => "nistp384",
                    521 => "nistp521",
                    _ => throw new CryptographicException($"Unsupported KeyLength: {ecdsa.KeySize}")
                },
                _ => throw new NotSupportedException($"Unsupported ECDSA curve: {oid.FriendlyName ?? oid.Value}")
            };
        }

        public static byte[] UncompressedCoords(this ECParameters ecdsaParameters)
        {
            var qx = ecdsaParameters.Q.X!;
            var qy = ecdsaParameters.Q.Y!;
            return UncompressedCoords(qx, qy);
        }

#if !NETSTANDARD
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
                _ => throw new CryptographicException($"Unexpected Curve Magic: {magic}")
            };
        }

        public static byte[] UncompressedCoords(this ECDsaCng ecdsa, byte[] qx, byte[] qy)
        {
            return UncompressedCoords(qx, qy);
        }
#endif
    }
}
