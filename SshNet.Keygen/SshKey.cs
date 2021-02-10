using System;
using System.Security.Cryptography;
using Chaos.NaCl;
using Renci.SshNet.Security;
using SshNet.Keygen.Extensions;
using SshNet.Keygen.SshKeyEncryption;

namespace SshNet.Keygen
{
    public static class SshKey
    {
        internal static readonly HashAlgorithmName DefaultHashAlgorithmName = HashAlgorithmName.SHA256;
        internal static readonly ISshKeyEncryption DefaultSshKeyEncryption = new SshKeyEncryptionNone();

        public static Key Generate()
        {
            return Generate<RsaKey>(2048);
        }

        public static Key Generate<TKey>(int keyLength = 0) where TKey : Key, new()
        {
            switch (Activator.CreateInstance(typeof(TKey)))
            {
                case ED25519Key:
                    if (keyLength != 0)
                        throw new CryptographicException("KeyLength is not valid for ED25519Key");
                    var rngCsp = new RNGCryptoServiceProvider();
                    var seed = new byte[Ed25519.PrivateKeySeedSizeInBytes];
                    rngCsp.GetBytes(seed);
                    Ed25519.KeyPairFromSeed(out var edPubKey, out var edKey, seed);

                    return new ED25519Key(edPubKey, edKey);
                case RsaKey:
                    var rsa = CreateRSA(keyLength);
                    var rsaParameters = rsa.ExportParameters(true);

                    return new RsaKey(
                        rsaParameters.Modulus.ToBigInteger2(),
                        rsaParameters.Exponent.ToBigInteger2(),
                        rsaParameters.D.ToBigInteger2(),
                        rsaParameters.P.ToBigInteger2(),
                        rsaParameters.Q.ToBigInteger2(),
                        rsaParameters.InverseQ.ToBigInteger2()
                    );
                case EcdsaKey:
                    var curve = keyLength switch
                    {
                        256 => ECCurve.CreateFromFriendlyName("nistp256"),
                        384 => ECCurve.CreateFromFriendlyName("nistp384"),
                        521 => ECCurve.CreateFromFriendlyName("nistp521"),
                        _ => throw new CryptographicException("Unsupported KeyLength")
                    };

                    var ecdsa = ECDsa.Create(curve);
                    var ecdsaParameters = ecdsa.ExportParameters(true);

                    return new EcdsaKey(ecdsa.EcCurveNameSshCompat(), ecdsaParameters.UncompressedCoords(), ecdsaParameters.D);
                default:
                    throw new CryptographicException("Unsupported KeyType");
            }
        }

        private static RSA CreateRSA(int keySize)
        {
            var rsa = RSA.Create();

            if (rsa is RSACryptoServiceProvider)
            {
                rsa.Dispose();
                return new RSACng(keySize);
            }

            rsa.KeySize = keySize;
            return rsa;
        }
    }
}