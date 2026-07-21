using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
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
            // leave the caller's stream open
            using var writer = new StreamWriter(stream, new UTF8Encoding(false), 1024, true);

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
                    // SSH.NET's ED25519Key takes the 32-byte RFC 8032 seed and derives the public key.
                    using var rngCsp = RandomNumberGenerator.Create();
                    var seed = new byte[32];
                    rngCsp.GetBytes(seed);
                    key = new ED25519Key(seed);
                    break;
                }
                case SshKeyType.RSA:
                {
                    using var rsa = CreateRSA(info.KeyLength);
                    key = ToRsaKey(rsa.ExportParameters(true));
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

        /// <summary>Wraps an existing <see cref="RSA"/> key as an SSH.NET key.</summary>
        /// <param name="rsa">The RSA key (must be exportable, including the private key).</param>
        /// <param name="comment">Optional key comment.</param>
        public static GeneratedPrivateKey FromKey(RSA rsa, string? comment = null)
        {
            var key = ToRsaKey(rsa.ExportParameters(true));
            key.Comment = comment ?? "";
            return new GeneratedPrivateKey(key, new SshKeyGenerateInfo(SshKeyType.RSA));
        }

        /// <summary>Wraps an existing <see cref="ECDsa"/> key as an SSH.NET key.</summary>
        /// <param name="ecdsa">The ECDSA key (must be exportable, including the private key).</param>
        /// <param name="comment">Optional key comment.</param>
        public static GeneratedPrivateKey FromKey(ECDsa ecdsa, string? comment = null)
        {
            var p = ecdsa.ExportParameters(true);
            var key = new EcdsaKey(ecdsa.EcCurveNameSshCompat(), p.UncompressedCoords(), p.D!);
            key.Comment = comment ?? "";
            return new GeneratedPrivateKey(key, new SshKeyGenerateInfo(SshKeyType.ECDSA));
        }

        /// <summary>Wraps an Ed25519 key given its raw 32-byte seed or 64-byte expanded (seed+public) key.</summary>
        /// <param name="key">32-byte RFC 8032 seed, or 64-byte OpenSSH expanded private key.</param>
        /// <param name="comment">Optional key comment.</param>
        public static GeneratedPrivateKey FromEd25519(byte[] key, string? comment = null)
        {
            if (key is null)
                throw new ArgumentNullException(nameof(key));

            var seed = new byte[32];
            switch (key.Length)
            {
                case 32:
                case 64: // seed || public
                    Buffer.BlockCopy(key, 0, seed, 0, 32);
                    break;
                default:
                    throw new ArgumentException("Ed25519 key must be a 32-byte seed or 64-byte expanded key.", nameof(key));
            }

            var ed = new ED25519Key(seed) { Comment = comment ?? "" };
            return new GeneratedPrivateKey(ed, new SshKeyGenerateInfo(SshKeyType.ED25519));
        }

#if NET8_0_OR_GREATER
        /// <summary>Imports an RSA or ECDSA private key from a PEM (PKCS#1, SEC1 or PKCS#8, optionally encrypted).</summary>
        /// <param name="pem">The PEM text.</param>
        /// <param name="passphrase">Passphrase for an encrypted PKCS#8 PEM, or null.</param>
        public static GeneratedPrivateKey FromPem(string pem, string? passphrase = null)
        {
            using var rsa = RSA.Create();
            if (TryImportPem(rsa, pem, passphrase))
                return FromKey(rsa);

            using var ecdsa = ECDsa.Create();
            if (TryImportPem(ecdsa, pem, passphrase))
                return FromKey(ecdsa);

            throw new CryptographicException("Could not import PEM as an RSA or ECDSA private key (wrong passphrase or unsupported key).");
        }

        private static bool TryImportPem(AsymmetricAlgorithm alg, string pem, string? passphrase)
        {
            try
            {
                if (string.IsNullOrEmpty(passphrase))
                    alg.ImportFromPem(pem);
                else
                    alg.ImportFromEncryptedPem(pem, passphrase);
                return true;
            }
            catch (ArgumentException) { return false; }      // no matching PEM label for this algorithm
            catch (CryptographicException) { return false; } // wrong algorithm or passphrase
        }
#else
        // ponytail: netstandard2.0/net48 BCL has no ImportFromPem; a hand-rolled ASN.1 PKCS#8 parser
        // is well over the ~40 line ceiling, so PEM import is net8.0-only. Upgrade path: port the parser
        // via System.Formats.Asn1 (already referenced) if older TFMs ever need it.
        /// <summary>PEM import is only available on .NET 8 or later.</summary>
        /// <param name="pem">The PEM text.</param>
        /// <param name="passphrase">Passphrase for an encrypted PKCS#8 PEM, or null.</param>
        public static GeneratedPrivateKey FromPem(string pem, string? passphrase = null)
        {
            throw new PlatformNotSupportedException("SshKey.FromPem requires .NET 8 or later (BCL ImportFromPem/ImportFromEncryptedPem).");
        }
#endif

        private static RsaKey ToRsaKey(RSAParameters p)
        {
            return new RsaKey(
                p.Modulus!.ToBigInteger2().ToByteArray().Reverse().ToBigInteger(),
                p.Exponent!.ToBigInteger2().ToByteArray().Reverse().ToBigInteger(),
                p.D!.ToBigInteger2().ToByteArray().Reverse().ToBigInteger(),
                p.P!.ToBigInteger2().ToByteArray().Reverse().ToBigInteger(),
                p.Q!.ToBigInteger2().ToByteArray().Reverse().ToBigInteger(),
                p.InverseQ!.ToBigInteger2().ToByteArray().Reverse().ToBigInteger()
            );
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