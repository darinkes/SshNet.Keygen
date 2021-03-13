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
        internal static readonly ISshKeyEncryption DefaultSshKeyEncryption = new SshKeyEncryptionNone();
        internal const SshKeyHashAlgorithmName DefaultHashAlgorithmName = SshKeyHashAlgorithmName.SHA256;
        private const SshKeyFormat DefaultSshKeyFormat = SshKeyFormat.OpenSSH;
        private const int DefaultEcdsaSshKeyLength = 256;
        private const int DefaultEd25519SshKeyLength = 256;
        private const int DefaultRsaSshKeyLength = 2048;
        private static readonly string DefaultSshKeyComment = $"{Environment.UserName}@{Environment.MachineName}";

        #region KeyToFile

        #region DefaultKey

        // All Default Key
        public static PrivateKeyFile Generate(string path, FileMode mode)
        {
            return Generate<RsaKey>(path, mode, DefaultSshKeyFormat, DefaultSshKeyEncryption, DefaultSshKeyComment);
        }

        // All Default Format Key
        public static PrivateKeyFile Generate(string path, FileMode mode, SshKeyFormat format)
        {
            return Generate<RsaKey>(path, mode, format, DefaultSshKeyEncryption, DefaultSshKeyComment);
        }

        // Set Encryption
        public static PrivateKeyFile Generate(string path, FileMode mode, ISshKeyEncryption encryption)
        {
            return Generate<RsaKey>(path, mode, DefaultSshKeyFormat, encryption, DefaultSshKeyComment);
        }

        // Set Encryption Format Key
        public static PrivateKeyFile Generate(string path, FileMode mode, SshKeyFormat format, ISshKeyEncryption encryption)
        {
            return Generate<RsaKey>(path, mode, format, encryption, DefaultSshKeyComment);
        }

        // Set Comment
        public static PrivateKeyFile Generate(string path, FileMode mode, string comment)
        {
            return Generate<RsaKey>(path, mode, DefaultSshKeyFormat, DefaultSshKeyEncryption, comment);
        }

        // Set Comment Format Key
        public static PrivateKeyFile Generate(string path, FileMode mode, SshKeyFormat format, string comment)
        {
            return Generate<RsaKey>(path, mode, format, DefaultSshKeyEncryption, comment);
        }

        // Set Encryption & Comment
        public static PrivateKeyFile Generate(string path, FileMode mode, ISshKeyEncryption encryption, string comment)
        {
            return Generate<RsaKey>(path, mode, DefaultSshKeyFormat, encryption, comment);
        }

        // Set Encryption & Comment Format Key
        public static PrivateKeyFile Generate(string path, FileMode mode, SshKeyFormat format, ISshKeyEncryption encryption, string comment)
        {
            return Generate<RsaKey>(path, mode, format, encryption, comment);
        }

        // Set Key Length
        public static PrivateKeyFile Generate(string path, FileMode mode, int keyLength)
        {
            return Generate<RsaKey>(path, mode,DefaultSshKeyFormat, DefaultSshKeyEncryption, keyLength, DefaultSshKeyComment);
        }

        // Set Key Length Format Key
        public static PrivateKeyFile Generate(string path, FileMode mode, SshKeyFormat format, int keyLength)
        {
            return Generate<RsaKey>(path, mode, format, DefaultSshKeyEncryption, keyLength, DefaultSshKeyComment);
        }

        // Set Key Length & Comment
        public static PrivateKeyFile Generate(string path, FileMode mode, int keyLength, string comment)
        {
            return Generate<RsaKey>(path, mode, DefaultSshKeyFormat, DefaultSshKeyEncryption, keyLength, comment);
        }

        // Set Key Length & Comment Format Key
        public static PrivateKeyFile Generate(string path, FileMode mode, SshKeyFormat format,  int keyLength, string comment)
        {
            return Generate<RsaKey>(path, mode, format,  DefaultSshKeyEncryption, keyLength, comment);
        }

        // Set Encryption, Key Length & Comment
        public static PrivateKeyFile Generate(string path, FileMode mode, ISshKeyEncryption encryption, int keyLength, string comment)
        {
            return Generate<RsaKey>(path, mode, DefaultSshKeyFormat, encryption, keyLength, comment);
        }

        // Set Encryption, Key Length & Comment
        public static PrivateKeyFile Generate(string path, FileMode mode, SshKeyFormat format, ISshKeyEncryption encryption, int keyLength, string comment)
        {
            return Generate<RsaKey>(path, mode, format, encryption, keyLength, comment);
        }

        #endregion

        // Default TKey
        public static PrivateKeyFile Generate<TKey>(string path, FileMode mode) where TKey : Key, new()
        {
            return Generate<TKey>(path, mode, DefaultSshKeyFormat, DefaultSshKeyEncryption, DefaultSshKeyComment);
        }

        // Default Format TKey
        public static PrivateKeyFile Generate<TKey>(string path, FileMode mode, SshKeyFormat format) where TKey : Key, new()
        {
            return Generate<TKey>(path, mode, format, DefaultSshKeyEncryption, DefaultSshKeyComment);
        }

        // Set Encryption
        public static PrivateKeyFile Generate<TKey>(string path, FileMode mode, ISshKeyEncryption encryption) where TKey : Key, new()
        {
            return Generate<TKey>(path, mode, DefaultSshKeyFormat, encryption, DefaultSshKeyComment);
        }

        // Set Encryption Format Key
        public static PrivateKeyFile Generate<TKey>(string path, FileMode mode, SshKeyFormat format, ISshKeyEncryption encryption) where TKey : Key, new()
        {
            return Generate<TKey>(path, mode, format, encryption, DefaultSshKeyComment);
        }

        // Set Comment
        public static PrivateKeyFile Generate<TKey>(string path, FileMode mode, string comment) where TKey : Key, new()
        {
            return Generate<TKey>(path, mode, DefaultSshKeyFormat, DefaultSshKeyEncryption, comment);
        }

        // Set Comment Format Key
        public static PrivateKeyFile Generate<TKey>(string path, FileMode mode, SshKeyFormat format, string comment) where TKey : Key, new()
        {
            return Generate<TKey>(path, mode, format, DefaultSshKeyEncryption, comment);
        }

        // Set Encryption & Comment
        public static PrivateKeyFile Generate<TKey>(string path, FileMode mode, ISshKeyEncryption encryption, string comment) where TKey : Key, new()
        {
            return Generate<TKey>(path, mode, DefaultSshKeyFormat, encryption, comment);
        }

        // Set Encryption & Comment
        public static PrivateKeyFile Generate<TKey>(string path, FileMode mode, SshKeyFormat format, ISshKeyEncryption encryption, string comment) where TKey : Key, new()
        {
            var keyLength = Activator.CreateInstance(typeof(TKey)) switch
            {
                ED25519Key => DefaultEd25519SshKeyLength,
                RsaKey => DefaultRsaSshKeyLength,
                EcdsaKey => DefaultEcdsaSshKeyLength,
                _ => throw new NotSupportedException($"Unsupported KeyType: {typeof(TKey)}")
            };

            return Generate<TKey>(path, mode, format, encryption, keyLength, comment);
        }

        // Set Key Length
        public static PrivateKeyFile Generate<TKey>(string path, FileMode mode, int keyLength) where TKey : Key, new()
        {
            return Generate<TKey>(path, mode, DefaultSshKeyFormat, DefaultSshKeyEncryption, keyLength, DefaultSshKeyComment);
        }

        // Set Key Length Format Key
        public static PrivateKeyFile Generate<TKey>(string path, FileMode mode, SshKeyFormat format, int keyLength) where TKey : Key, new()
        {
            return Generate<TKey>(path, mode, format, DefaultSshKeyEncryption, keyLength, DefaultSshKeyComment);
        }

        // Set Key Length & Comment
        public static PrivateKeyFile Generate<TKey>(string path, FileMode mode, int keyLength, string comment) where TKey : Key, new()
        {
            return Generate<TKey>(path, mode, DefaultSshKeyFormat, DefaultSshKeyEncryption, keyLength, comment);
        }

        // Set Key Length & Comment Format Key
        public static PrivateKeyFile Generate<TKey>(string path, FileMode mode, SshKeyFormat format, int keyLength, string comment) where TKey : Key, new()
        {
            return Generate<TKey>(path, mode, format, DefaultSshKeyEncryption, keyLength, comment);
        }

        // Set Encryption, Key Length & Comment
        public static PrivateKeyFile Generate<TKey>(string path, FileMode mode, ISshKeyEncryption encryption, int keyLength, string? comment) where TKey : Key, new()
        {
            return Generate<TKey>(path, mode, DefaultSshKeyFormat, encryption, keyLength, comment);
        }

        // Set Encryption, Key Length & Comment Format Key
        public static PrivateKeyFile Generate<TKey>(string path, FileMode mode, SshKeyFormat format, ISshKeyEncryption encryption, int keyLength, string? comment) where TKey : Key, new()
        {
            var key = Generate<TKey>(keyLength, comment);

            using var file = File.Open(path, mode, FileAccess.Write);
            using var writer = new StreamWriter(file);

            switch (format)
            {
                case SshKeyFormat.OpenSSH:
                    writer.Write(key.ToOpenSshFormat(encryption));
                    break;
                case SshKeyFormat.PuTTY:
                    writer.Write(key.ToPuttyFormat(encryption));
                    break;
                default:
                    throw new NotSupportedException($"Not supported Key Format {format}");
            }

            using var pubFile = File.Open($"{path}.pub", mode);
            using var pubWriter = new StreamWriter(pubFile);
            pubWriter.Write(key.ToPublic());
            return key;
        }

        #endregion

        #region KeyToObject

        #region DefaultKey

        // All Default Key
        public static PrivateKeyFile Generate()
        {
            return Generate<RsaKey>(DefaultSshKeyComment);
        }

        // Set Comment
        public static PrivateKeyFile Generate(string comment)
        {
            return Generate<RsaKey>(comment);
        }

        // Set Key Length
        public static PrivateKeyFile Generate(int keyLength)
        {
            return Generate<RsaKey>(keyLength, DefaultSshKeyComment);
        }

        // Set Key Length & Comment
        public static PrivateKeyFile Generate(int keyLength, string comment)
        {
            return Generate<RsaKey>(keyLength, comment);
        }

        #endregion

        // Default TKey
        public static PrivateKeyFile Generate<TKey>() where TKey : Key, new()
        {
            return Generate<TKey>(DefaultSshKeyComment);
        }

        // Set Comment
        public static PrivateKeyFile Generate<TKey>(string comment) where TKey : Key, new()
        {
            var keyLength = Activator.CreateInstance(typeof(TKey)) switch
            {
                ED25519Key => DefaultEd25519SshKeyLength,
                RsaKey => DefaultRsaSshKeyLength,
                EcdsaKey => DefaultEcdsaSshKeyLength,
                _ => throw new NotSupportedException($"Unsupported KeyType: {typeof(TKey)}")
            };
            return Generate<TKey>(keyLength, comment);
        }

        // Set Key Length
        public static PrivateKeyFile Generate<TKey>(int keyLength) where TKey : Key, new()
        {
            return Generate<TKey>(keyLength, DefaultSshKeyComment);
        }

        // Set Key Length & Comment
        public static PrivateKeyFile Generate<TKey>(int keyLength, string? comment) where TKey : Key, new()
        {
            Key key;
            switch (Activator.CreateInstance(typeof(TKey)))
            {
                case ED25519Key:
                {
                    using var rngCsp = new RNGCryptoServiceProvider();
                    var seed = new byte[Ed25519.PrivateKeySeedSizeInBytes];
                    rngCsp.GetBytes(seed);
                    Ed25519.KeyPairFromSeed(out var edPubKey, out var edKey, seed);
                    key = new ED25519Key(edPubKey, edKey.Reverse());
                    break;
                }
                case RsaKey:
                {
                    using var rsa = CreateRSA(keyLength);
                    var rsaParameters = rsa.ExportParameters(true);

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
                case EcdsaKey:
                {
#if NETSTANDARD
                    var curve = keyLength switch
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
                        ecdsaParameters.D
                    );
#else
                    using var ecdsa = new ECDsaCng(keyLength);
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
                    throw new NotSupportedException($"Unsupported KeyType: {typeof(TKey)}");
            }

            key.Comment = comment ?? DefaultSshKeyComment;
            return new PrivateKeyFile(key);
        }

        #endregion

        private static RSA CreateRSA(int keySize)
        {
#if NET40
            var rsa = new RSACryptoServiceProvider(keySize);
            var keySizes = rsa.LegalKeySizes[0];
            if (keySize < keySizes.MinSize || keySize > keySizes.MaxSize)
            {
                throw new CryptographicException($"Illegal Keysize: {keySize}");
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