using System;
using System.IO;
using System.Security.Cryptography;
using Chaos.NaCl;
using Renci.SshNet.Security;
using SshNet.Keygen.Extensions;

namespace SshNet.Keygen
{
    /// <summary>
    /// Generates SSH authentication keys (RSA, ECDSA, Ed25519).
    /// </summary>
    public static class SshKey
    {
        /// <summary>Starts a fluent <see cref="SshKeyBuilder"/> for the given key type.</summary>
        /// <param name="keyType">The key algorithm to generate.</param>
        public static SshKeyBuilder Builder(SshKeyType keyType = SshKeyGenerateInfo.DefaultSshKeyType)
        {
            return new SshKeyBuilder(keyType);
        }

        /// <summary>Generates a default key and writes it to <paramref name="path"/>.</summary>
        /// <param name="path">Destination file path.</param>
        /// <param name="mode">How the destination file is opened.</param>
        public static GeneratedPrivateKey Generate(string path, FileMode mode)
        {
            return Generate(path, mode, new SshKeyGenerateInfo());
        }

        /// <summary>Generates a key per <paramref name="info"/> and writes it to <paramref name="path"/>.</summary>
        /// <param name="path">Destination file path.</param>
        /// <param name="mode">How the destination file is opened.</param>
        /// <param name="info">Generation and export options.</param>
        public static GeneratedPrivateKey Generate(string path, FileMode mode, SshKeyGenerateInfo info)
        {
            using var file = File.Open(path, mode, FileAccess.Write);
            return Generate(file, info);
        }

        /// <summary>Generates a key per <paramref name="info"/> and writes it to <paramref name="stream"/>.</summary>
        /// <param name="stream">Destination stream.</param>
        /// <param name="info">Generation and export options.</param>
        public static GeneratedPrivateKey Generate(Stream stream, SshKeyGenerateInfo info)
        {
            using var writer = new StreamWriter(stream);

            var key = Generate(info);
            switch (info.KeyFormat)
            {
                case SshKeyFormat.OpenSSH:
                    writer.Write(key.ToOpenSshFormat(info.Encryption));
                    break;
                case SshKeyFormat.PuTTYv2:
                case SshKeyFormat.PuTTYv3:
                    writer.Write(key.ToPuttyFormat(info.Encryption, info.KeyFormat));
                    break;
                default:
                    throw new NotSupportedException($"Not supported Key Format {info.KeyFormat}");
            }
            return key;
        }

        /// <summary>Generates a default key (2048-bit RSA) in memory.</summary>
        public static GeneratedPrivateKey Generate()
        {
            return Generate(new SshKeyGenerateInfo());
        }

        /// <summary>Generates a key per <paramref name="info"/> in memory.</summary>
        /// <param name="info">Generation and export options.</param>
        public static GeneratedPrivateKey Generate(SshKeyGenerateInfo info)
        {
            Key key;
            switch (info.KeyType)
            {
                case SshKeyType.ED25519:
                {
                    using var rngCsp = RandomNumberGenerator.Create();
                    var seed = new byte[Ed25519.PrivateKeySeedSizeInBytes];
                    rngCsp.GetBytes(seed);
                    Ed25519.KeyPairFromSeed(out _, out var edKey, seed);
                    key = new ED25519Key(edKey.Reverse());
                    break;
                }
                case SshKeyType.RSA:
                {
                    using var rsa = CreateRSA(info.KeyLength);
                    var rsaParameters = rsa.ExportParameters(true);

                    key = new RsaKey(
                        rsaParameters.Modulus!.ToBigInteger2().ToByteArray().Reverse().ToBigInteger(),
                        rsaParameters.Exponent!.ToBigInteger2().ToByteArray().Reverse().ToBigInteger(),
                        rsaParameters.D!.ToBigInteger2().ToByteArray().Reverse().ToBigInteger(),
                        rsaParameters.P!.ToBigInteger2().ToByteArray().Reverse().ToBigInteger(),
                        rsaParameters.Q!.ToBigInteger2().ToByteArray().Reverse().ToBigInteger(),
                        rsaParameters.InverseQ!.ToBigInteger2().ToByteArray().Reverse().ToBigInteger()
                    );
                    break;
                }
                case SshKeyType.ECDSA:
                {
#if NETSTANDARD
                    var curve = info.KeyLength switch
                    {
                        256 => ECCurve.CreateFromFriendlyName("nistp256"),
                        384 => ECCurve.CreateFromFriendlyName("nistp384"),
                        521 => ECCurve.CreateFromFriendlyName("nistp521"),
                        _ => throw new CryptographicException("Unsupported KeyLength")
                    };

                    using var ecdsa = ECDsa.Create();
                    if (ecdsa is null)
                        throw new CryptographicException("Unable to generate ECDSA");
                    ecdsa.GenerateKey(curve);
                    var ecdsaParameters = ecdsa.ExportParameters(true);

                    key = new EcdsaKey(
                        ecdsa.EcCurveNameSshCompat(),
                        ecdsaParameters.UncompressedCoords(),
                        ecdsaParameters.D!
                    );
#else
                    using var ecdsa = new ECDsaCng(info.KeyLength);
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
#elif NET8_0_OR_GREATER
            var rsa = RSA.Create();
            rsa.KeySize = keySize;
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