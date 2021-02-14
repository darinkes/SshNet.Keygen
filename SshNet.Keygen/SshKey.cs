using System;
using System.IO;
using System.Security.Cryptography;
using Chaos.NaCl;
using Renci.SshNet;
using Renci.SshNet.Security;
using SshNet.Keygen.Extensions;
using SshNet.Keygen.SshKeyEncryption;

namespace SshNet.Keygen
{
    public static class SshKey
    {
        internal static readonly HashAlgorithmName DefaultHashAlgorithmName = HashAlgorithmName.SHA256;
        internal static readonly ISshKeyEncryption DefaultSshKeyEncryption = new SshKeyEncryptionNone();

        public static PrivateKeyFile Generate(string path, FileMode mode, int keyLength = 2048, string comment = "")
        {
            return Generate<RsaKey>(path, mode,  DefaultSshKeyEncryption, keyLength, comment);
        }

        public static PrivateKeyFile Generate(string path, FileMode mode, ISshKeyEncryption encryption, int keyLength = 2048, string comment = "")
        {
            return Generate<RsaKey>(path, mode, encryption, keyLength, comment);
        }

        public static PrivateKeyFile Generate<TKey>(string path, FileMode mode, int keyLength = 0, string comment = "") where TKey : Key, new()
        {
            return Generate<TKey>(path, mode, DefaultSshKeyEncryption, keyLength, comment);
        }

        public static PrivateKeyFile Generate<TKey>(string path, FileMode mode, ISshKeyEncryption encryption, int keyLength = 0, string comment = "") where TKey : Key, new()
        {
            var key = Generate<TKey>(keyLength);

            using var file = File.Open(path, mode, FileAccess.Write);
            using var writer = new StreamWriter(file);
            writer.Write(key.ToOpenSshFormat(encryption, comment));

            using var pubFile = File.Open($"{path}.pub", mode);
            using var pubWriter = new StreamWriter(pubFile);
            pubWriter.Write(key.ToOpenSshPublicFormat(comment));

            return key;
        }

        public static PrivateKeyFile Generate(int keyLength = 2048)
        {
            return Generate<RsaKey>(keyLength);
        }

        public static PrivateKeyFile Generate<TKey>(int keyLength = 0) where TKey : Key, new()
        {
            Key key;
            switch (Activator.CreateInstance(typeof(TKey)))
            {
                case ED25519Key:
                    if (keyLength != 0)
                        throw new CryptographicException("KeyLength is not valid for ED25519Key");
                    var rngCsp = new RNGCryptoServiceProvider();
                    var seed = new byte[Ed25519.PrivateKeySeedSizeInBytes];
                    rngCsp.GetBytes(seed);
                    Ed25519.KeyPairFromSeed(out var edPubKey, out var edKey, seed);

                    key = new ED25519Key(edPubKey, edKey);
                    break;
                case RsaKey:
                    var rsa = CreateRSA(keyLength);
                    var rsaParameters = rsa.ExportParameters(true);

                    key = new RsaKey(
                        rsaParameters.Modulus.ToBigInteger2(),
                        rsaParameters.Exponent.ToBigInteger2(),
                        rsaParameters.D.ToBigInteger2(),
                        rsaParameters.P.ToBigInteger2(),
                        rsaParameters.Q.ToBigInteger2(),
                        rsaParameters.InverseQ.ToBigInteger2()
                    );
                    break;
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

                    key = new EcdsaKey(
                        ecdsa.EcCurveNameSshCompat(),
                        ecdsaParameters.UncompressedCoords(),
                        ecdsaParameters.D
                    );
                    break;
                default:
                    throw new CryptographicException("Unsupported KeyType");
            }

            // ToDo: could we set the Key in PrivateKeyFile directly?
            //       Currently there is no ctor with HostKey
            return new PrivateKeyFile(key.ToOpenSshFormat().ToStream());
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