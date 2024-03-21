using System;
using System.IO;
using System.Security.Cryptography;
using Chaos.NaCl;
using Renci.SshNet.Security;
using SshNet.Keygen.Extensions;

namespace SshNet.Keygen
{
    public static class SshKey
    {
        public static GeneratedPrivateKey Generate(string path, FileMode mode)
        {
            return Generate(path, mode, new SshKeyGenerateInfo());
        }

        public static GeneratedPrivateKey Generate(string path, FileMode mode, SshKeyGenerateInfo info)
        {
            using var file = File.Open(path, mode, FileAccess.Write);
            return Generate(file, info);
        }

        public static GeneratedPrivateKey Generate(Stream stream, SshKeyGenerateInfo info)
        {
            using var writer = new StreamWriter(stream);

            var key = Generate(info);
            switch (info.KeyFormat)
            {
                case SshKeyFormat.OpenSSH:
                    writer.Write(key.ToOpenSshFormat(info.Encryption));
                    break;
                case SshKeyFormat.PuTTY:
                    writer.Write(key.ToPuttyFormat(info.Encryption));
                    break;
                default:
                    throw new NotSupportedException($"Not supported Key Format {info.KeyFormat}");
            }
            return key;
        }

        public static GeneratedPrivateKey Generate()
        {
            return Generate(new SshKeyGenerateInfo());
        }

        public static GeneratedPrivateKey Generate(SshKeyGenerateInfo info)
        {
            Key key;
            switch (info.KeyType)
            {
                case SshKeyType.ED25519:
                {
                    using var rngCsp = new RNGCryptoServiceProvider();
                    var seed = new byte[Ed25519.PrivateKeySeedSizeInBytes];
                    rngCsp.GetBytes(seed);
                    Ed25519.KeyPairFromSeed(out _, out var edKey, seed);
                    key = new ED25519Key(edKey.Reverse());
                    break;
                }
                case SshKeyType.RSA:
                {
                    RSAParameters rsaParameters;
                    if (info.Rsa is not null)
                    {
                        rsaParameters = info.Rsa.ExportParameters(true);
                    }
                    else
                    {
                        using var rsa = CreateRSA(info.KeyLength);
                        rsaParameters = rsa.ExportParameters(true);
                    }

                    key = new RsaKey(
                        rsaParameters.Modulus.ToBigInteger2().ToByteArray().Reverse().ToBigInteger(),
                        rsaParameters.Exponent.ToBigInteger2().ToByteArray().Reverse().ToBigInteger(),
                        rsaParameters.D.ToBigInteger2().ToByteArray().Reverse().ToBigInteger(),
                        rsaParameters.P.ToBigInteger2().ToByteArray().Reverse().ToBigInteger(),
                        rsaParameters.Q.ToBigInteger2().ToByteArray().Reverse().ToBigInteger(),
                        rsaParameters.InverseQ.ToBigInteger2().ToByteArray().Reverse().ToBigInteger()
                    );
                    break;
                }
                case SshKeyType.ECDSA:
                {
                    var dispose = false;
#if NETSTANDARD
                    ECDsa? ecdsa;
                    if (info.Ecdsa is not null)
                    {
                        ecdsa = info.Ecdsa;
                    }
                    else
                    {
                        var curve = info.KeyLength switch
                        {
                            256 => ECCurve.CreateFromFriendlyName("nistp256"),
                            384 => ECCurve.CreateFromFriendlyName("nistp384"),
                            521 => ECCurve.CreateFromFriendlyName("nistp521"),
                            _ => throw new CryptographicException("Unsupported KeyLength")
                        };

                        ecdsa = ECDsa.Create();
                        if (ecdsa is null)
                            throw new CryptographicException("Unable to generate ECDSA");
                        dispose = true;
                        ecdsa.GenerateKey(curve);
                    }

                    var ecParameters = ecdsa.ExportParameters(true);

                    key = new EcdsaKey(
                        ecdsa.EcCurveNameSshCompat(),
                        ecParameters.UncompressedCoords(),
                        ecParameters.D
                    );
#else
                    ECDsaCng ecdsa;
                    if (info.Ecdsa is not null)
                    {
                        ecdsa = info.Ecdsa;
                    }
                    else
                    {
                        ecdsa = new ECDsaCng(info.KeyLength);
                        dispose = true;
                    }

                    var keyBlob = ecdsa.Key.Export(CngKeyBlobFormat.EccPrivateBlob);
                    using var stream = new MemoryStream(keyBlob);
                    using var reader = new BinaryReader(stream);
                    var magic = (EcdsaExtension.KeyBlobMagicNumber)reader.ReadInt32();
                    var coordLength = reader.ReadInt32();
                    var qx = reader.ReadBytes(coordLength);
                    var qy = reader.ReadBytes(coordLength);
                    var d = reader.ReadBytes(coordLength);

                    key = new EcdsaKey(
                        ecdsa.EcCurveNameSshCompat(magic),
                        ecdsa.UncompressedCoords(qx, qy),
                        d
                    );
#endif
                    if (dispose)
                        ecdsa.Dispose();
                    break;
                }
                default:
                    throw new NotSupportedException($"Unsupported KeyType: {info.KeyType}");
            }

            key.Comment = info.Comment;
            return new GeneratedPrivateKey(key, info);
        }

        private static RSA CreateRSA(int keySize)
        {
#if NET40
            var rsa = new RSACryptoServiceProvider(keySize);
            var keySizes = rsa.LegalKeySizes[0];
            if (keySize < keySizes.MinSize || keySize > keySizes.MaxSize)
            {
                throw new CryptographicException($"Illegal Key Size: {keySize}");
            }
            return rsa;
#else
            var rsa = RSA.Create();

            if (rsa is RSACryptoServiceProvider)
            {
                rsa.Dispose();
                return new RSACng(keySize);
            }

            rsa.KeySize = keySize;
            return rsa;
#endif
        }
    }
}