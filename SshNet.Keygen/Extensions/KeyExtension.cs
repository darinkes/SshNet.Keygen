using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Renci.SshNet.Security;
using SshNet.Keygen.SshKeyEncryption;

namespace SshNet.Keygen.Extensions
{
    public static class KeyExtension
    {
        #region Fingerprint

        public static string Fingerprint(this Key key)
        {
            return key.Fingerprint(SshKeyGenerateInfo.DefaultHashAlgorithmName);
        }

        public static string Fingerprint(this Key key, SshKeyHashAlgorithmName hashAlgorithm)
        {
            using var pubStream = new MemoryStream();
            using var pubWriter = new BinaryWriter(pubStream);
            key.PublicKeyData(pubWriter);

            using var hash = SshKeyHashAlgorithm.Create(hashAlgorithm);
            var pubKeyHash = hash.ComputeHash(pubStream.ToArray());

            var base64 = hashAlgorithm == SshKeyHashAlgorithmName.MD5
                ? BitConverter.ToString(pubKeyHash).ToLower().Replace('-', ':')
                : Convert.ToBase64String(pubKeyHash, 0, pubKeyHash.Length).TrimEnd('=');

            return $"{key.KeyLength} {SshKeyHashAlgorithm.HashAlgorithmName(hashAlgorithm)}:{base64} {key.Comment ?? ""} ({key.KeyName()})";
        }

        #endregion

        #region Public

        public static string ToPublic(this Key key)
        {
            using var pubStream = new MemoryStream();
            using var pubWriter = new BinaryWriter(pubStream);
            key.PublicKeyData(pubWriter);

            var base64 = Convert.ToBase64String(pubStream.ToArray());
            return $"{key} {base64} {key.Comment ?? ""}\n";
        }

        #endregion

        #region OpenSshFormat

        public static string ToOpenSshFormat(this Key key)
        {
            return key.ToOpenSshFormat(SshKeyGenerateInfo.DefaultSshKeyEncryption);
        }

        public static string ToOpenSshFormat(this Key key, ISshKeyEncryption encryption)
        {
            var s = new StringWriter();
            s.Write("-----BEGIN OPENSSH PRIVATE KEY-----\n");
            s.Write(key.OpensshPrivateKeyData(encryption));
            s.Write("-----END OPENSSH PRIVATE KEY-----\n");
            return s.ToString();
        }

        private static string KeyName(this Key key)
        {
            switch (key.ToString())
            {
                case "ssh-ed25519":
                    return "ED25519";
                case "ssh-rsa":
                    return "RSA";
                case "ecdsa-sha2-nistp256":
                    // Fallthrough
                case "ecdsa-sha2-nistp384":
                    // Fallthrough
                case "ecdsa-sha2-nistp521":
                    return "ECDSA";
                default:
                    throw new NotSupportedException($"Unsupported KeyType: {key}");
            }
        }

        private static string OpensshPrivateKeyData(this Key key, ISshKeyEncryption encryption)
        {
            using var stream = new MemoryStream();
            using var writer = new BinaryWriter(stream);

            writer.EncodeNullTerminatedString("openssh-key-v1"); // Auth Magic
            writer.EncodeBinary(encryption.CipherName);
            writer.EncodeBinary(encryption.KdfName);
            writer.EncodeBinary(encryption.KdfOptions());
            writer.EncodeUInt(1); // Number of Keys

            // public key in ssh-format
            using var pubStream = new MemoryStream();
            using var pubWriter = new BinaryWriter(pubStream);
            key.PublicKeyData(pubWriter);
            writer.EncodeBinary(pubStream);

            // private key
            using var privStream = new MemoryStream();
            using var privWriter = new BinaryWriter(privStream);

            var rnd = new Random().Next(0, int.MaxValue);
            privWriter.EncodeInt(rnd); // check-int1
            privWriter.EncodeInt(rnd); // check-int2
            privWriter.EncodeBinary(key.ToString());
            switch (key.ToString())
            {
                case "ssh-ed25519":
                    var ed25519 = (ED25519Key)key;
                    privWriter.EncodeBinary(ed25519.PublicKey);
                    privWriter.EncodeBinary(ed25519.PrivateKey);
                    break;
                case "ssh-rsa":
                    var rsa = (RsaKey)key;
                    privWriter.EncodeBinary(rsa.Modulus);
                    privWriter.EncodeBinary(rsa.Exponent);
                    privWriter.EncodeBinary(rsa.D);
                    privWriter.EncodeBinary(rsa.InverseQ);
                    privWriter.EncodeBinary(rsa.P);
                    privWriter.EncodeBinary(rsa.Q);
                    break;
                case "ecdsa-sha2-nistp256":
                    // Fallthrough
                case "ecdsa-sha2-nistp384":
                    // Fallthrough
                case "ecdsa-sha2-nistp521":
                    var ecdsa = (EcdsaKey)key;
                    var publicKey = ecdsa.Public;
                    privWriter.EncodeBinary(publicKey[0]);
                    privWriter.EncodeBinary(publicKey[1]);
                    privWriter.EncodeBinary(ecdsa.PrivateKey.ToBigInteger2());
                    break;
                default:
                    throw new NotSupportedException($"Unsupported KeyType: {key}");
            }
            // comment
            privWriter.EncodeBinary(key.Comment ?? "");

            // private key padding (1, 2, 3, ...)
            var pad = 0;
            while (privStream.Length % encryption.BlockSize != 0)
            {
                privWriter.Write((byte)++pad);
            }

            writer.EncodeBinary(encryption.Encrypt(privStream.ToArray()));

            // Content as Base64
            var base64 = Convert.ToBase64String(stream.ToArray()).ToCharArray();
            var pem = new StringWriter();
            for (var i = 0; i < base64.Length; i += 70)
            {
                pem.Write(base64, i, Math.Min(70, base64.Length - i));
                pem.Write("\n");
            }

            return pem.ToString();
        }

        #endregion

        #region PuttyFormat

        public static string ToPuttyFormat(this Key key)
        {
            return key.ToPuttyFormat(SshKeyGenerateInfo.DefaultSshKeyEncryption);
        }

        public static string ToPuttyFormat(this Key key, ISshKeyEncryption encryption)
        {
            // Public Key
            using var pubStream = new MemoryStream();
            using var pubWriter = new BinaryWriter(pubStream);
            key.PublicKeyData(pubWriter);

            var publicBase64String = Convert.ToBase64String(pubStream.ToArray()).FormatNewLines(64);

            // Private Key
            using var privStream = new MemoryStream();
            using var privWriter = new BinaryWriter(privStream);
            switch (key.ToString())
            {
                case "ssh-ed25519":
                    var ed25519 = (ED25519Key)key;
                    privWriter.EncodeBinary(ed25519.PrivateKey);
                    break;
                case "ssh-rsa":
                    var rsa = (RsaKey)key;
                    privWriter.EncodeBinary(rsa.D);
                    privWriter.EncodeBinary(rsa.P);
                    privWriter.EncodeBinary(rsa.Q);
                    privWriter.EncodeBinary(rsa.InverseQ);
                    break;
                case "ecdsa-sha2-nistp256":
                    // Fallthrough
                case "ecdsa-sha2-nistp384":
                    // Fallthrough
                case "ecdsa-sha2-nistp521":
                    var ecdsa = (EcdsaKey)key;
                    privWriter.EncodeBinary(ecdsa.PrivateKey.ToBigInteger2());
                    break;
                default:
                    throw new NotSupportedException($"Unsupported KeyType: {key}");
            }

            // private key padding (1, 2, 3, ...)
            var pad = 0;
            while (privStream.Length % 16 != 0)
            {
                privWriter.Write((byte)++pad);
            }

            var encrypted = encryption.PuttyEncrypt(privStream.ToArray());
            var privateBase64String = Convert.ToBase64String(encrypted).FormatNewLines(64);

            // MAC
            using var macStream = new MemoryStream();
            using var macWriter = new BinaryWriter(macStream);
            macWriter.EncodeBinary(key.ToString());
            macWriter.EncodeBinary(encryption.CipherName);
            macWriter.EncodeBinary(key.Comment ?? "");
            macWriter.EncodeBinary(pubStream);
            macWriter.EncodeBinary(privStream);

            var hashData = macStream.ToArray();

            using var sha1 = SHA1.Create();
            var macKey = sha1.ComputeHash(Encoding.ASCII.GetBytes("putty-private-key-file-mac-key" + encryption.Passphrase));
            using var hmac = new HMACSHA1(macKey);
            var macHash = hmac.ComputeHash(hashData);

            var s = new StringWriter();
            s.Write($"PuTTY-User-Key-File-2: {key}\n");
            s.Write($"Encryption: {encryption.CipherName}\n");
            s.Write($"Comment: {key.Comment ?? ""}\n");
            s.Write($"Public-Lines: {publicBase64String.Split('\n').Length}\n");
            s.Write($"{publicBase64String}\n");
            s.Write($"Private-Lines: {privateBase64String.Split('\n').Length}\n");
            s.Write($"{privateBase64String}\n");
            s.Write($"Private-MAC: {BitConverter.ToString(macHash).Replace("-", "").ToLower()}\n");
            return s.ToString();
        }

        #endregion

        private static void PublicKeyData(this Key key, BinaryWriter writer)
        {
            writer.EncodeBinary(key.ToString());
            switch (key.ToString())
            {
                case "ssh-ed25519":
                    var ed25519 = (ED25519Key)key;
                    writer.EncodeBinary(ed25519.PublicKey);
                    break;
                case "ssh-rsa":
                    var rsa = (RsaKey)key;
                    writer.EncodeBinary(rsa.Exponent);
                    writer.EncodeBinary(rsa.Modulus);
                    break;
                case "ecdsa-sha2-nistp256":
                // Fallthrough
                case "ecdsa-sha2-nistp384":
                // Fallthrough
                case "ecdsa-sha2-nistp521":
                    var ecdsa = (EcdsaKey)key;
                    var publicKey = ecdsa.Public;
                    writer.EncodeBinary(publicKey[0]);
                    writer.EncodeBinary(publicKey[1]);
                    break;
                default:
                    throw new NotSupportedException($"Unsupported KeyType: {key}");
            }
        }
    }
}