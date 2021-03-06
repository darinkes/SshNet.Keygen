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
        public static string ToOpenSshFormat(this Key key, string comment = "")
        {
            return key.ToOpenSshFormat(SshKey.DefaultSshKeyEncryption, comment);
        }

        public static string ToOpenSshFormat(this Key key, ISshKeyEncryption encryption, string comment = "")
        {
            var s = new StringWriter();
            s.Write("-----BEGIN OPENSSH PRIVATE KEY-----\n");
            s.Write(key.PrivateKeyData(encryption, comment));
            s.Write("-----END OPENSSH PRIVATE KEY-----\n");
            return s.ToString();
        }

        public static string ToOpenSshPublicFormat(this Key key, string comment = "")
        {
            using var pubStream = new MemoryStream();
            using var pubWriter = new BinaryWriter(pubStream);
            key.PublicKeyData(pubWriter);
            var base64 = Convert.ToBase64String(pubStream.GetBuffer(), 0, (int)pubStream.Length).ToCharArray();

            var stringBuilder = new StringBuilder();
            stringBuilder.Append(key);
            stringBuilder.Append(' ');
            stringBuilder.Append(base64);
            if (!string.IsNullOrEmpty(comment))
            {
                stringBuilder.Append(' ');
                stringBuilder.Append(comment);
            }
            stringBuilder.Append('\n');
            return stringBuilder.ToString();
        }

        public static string Fingerprint(this Key key, string comment = "")
        {
            return key.Fingerprint(SshKey.DefaultHashAlgorithmName, comment);
        }

        public static string Fingerprint(this Key key, SshKeyHashAlgorithmName hashAlgorithm, string comment = "")
        {
            // SHA256 of PublicKey-Data
            using var pubStream = new MemoryStream();
            using var pubWriter = new BinaryWriter(pubStream);
            key.PublicKeyData(pubWriter);
            byte[] pubKeyHash;

            using (var hash = SshKeyHashAlgorithm.Create(hashAlgorithm))
            {
                if (hash == null)
                    throw new CryptographicException($"Unsupported HashAlgorithmName: {hashAlgorithm}");
                pubKeyHash = hash.ComputeHash(pubStream.GetBuffer(), 0, (int)pubStream.Length);
            }

            // base64 without padding or Hex
            var base64 = hashAlgorithm == SshKeyHashAlgorithmName.MD5 ?
                BitConverter.ToString(pubKeyHash).ToLower().Replace('-', ':') :
                Convert.ToBase64String(pubKeyHash, 0, (int)pubKeyHash.Length).TrimEnd('=');

            return $"{key.KeyLength} {SshKeyHashAlgorithm.HashAlgorithmName(hashAlgorithm)}:{base64} {comment} ({key.KeyName()})";
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
            }

            throw new Exception("Unknown KeyType");
        }

        private static void PublicKeyData(this Key key, BinaryWriter writer)
        {
            writer.EncodeString(key.ToString());
            switch (key.ToString())
            {
                case "ssh-ed25519":
                    var ed25519 = (ED25519Key)key;
                    writer.EncodeBignum2(ed25519.PublicKey);
                    break;
                case "ssh-rsa":
                    var rsa = (RsaKey)key;
                    writer.EncodeBignum2(rsa.Exponent.ToByteArray().Reverse());
                    writer.EncodeBignum2(rsa.Modulus.ToByteArray().Reverse());
                    break;
                case "ecdsa-sha2-nistp256":
                    // Fallthrough
                case "ecdsa-sha2-nistp384":
                    // Fallthrough
                case "ecdsa-sha2-nistp521":
                    var ecdsa = (EcdsaKey)key;
                    // writer.EncodeEcKey(ecdsa.Ecdsa, false);
                    var publicKey = ecdsa.Public;
                    writer.EncodeString(publicKey[0].ToByteArray().Reverse());
                    writer.EncodeString(publicKey[1].ToByteArray().Reverse());
                    break;
            }
        }

        private static string PrivateKeyData(this Key key, ISshKeyEncryption encryption, string comment)
        {
            using var stream = new MemoryStream();
            using var writer = new BinaryWriter(stream);

            writer.EncodeNullTerminatedString("openssh-key-v1"); // Auth Magic
            writer.EncodeString(encryption.CipherName);
            writer.EncodeString(encryption.KdfName);
            writer.EncodeString(encryption.KdfOptions());
            writer.EncodeUInt(1); // Number of Keys

            // public key in ssh-format
            using var pubStream = new MemoryStream();
            using var pubWriter = new BinaryWriter(pubStream);
            key.PublicKeyData(pubWriter);
            writer.EncodeString(pubStream);

            // private key
            using var privStream = new MemoryStream();
            using var privWriter = new BinaryWriter(privStream);

            var rnd = new Random().Next(0, int.MaxValue);
            privWriter.EncodeInt(rnd); // check-int1
            privWriter.EncodeInt(rnd); // check-int2
            privWriter.EncodeString(key.ToString());
            switch (key.ToString())
            {
                case "ssh-ed25519":
                    var ed25519 = (ED25519Key)key;
                    privWriter.EncodeBignum2(ed25519.PublicKey);
                    privWriter.EncodeBignum2(ed25519.PrivateKey);
                    break;
                case "ssh-rsa":
                    var rsa = (RsaKey)key;
                    privWriter.EncodeBignum2(rsa.Modulus.ToByteArray().Reverse());
                    privWriter.EncodeBignum2(rsa.Exponent.ToByteArray().Reverse());
                    privWriter.EncodeBignum2(rsa.D.ToByteArray().Reverse());
                    privWriter.EncodeBignum2(rsa.InverseQ.ToByteArray().Reverse());
                    privWriter.EncodeBignum2(rsa.P.ToByteArray().Reverse());
                    privWriter.EncodeBignum2(rsa.Q.ToByteArray().Reverse());
                    break;
                case "ecdsa-sha2-nistp256":
                    // Fallthrough
                case "ecdsa-sha2-nistp384":
                    // Fallthrough
                case "ecdsa-sha2-nistp521":
                    var ecdsa = (EcdsaKey)key;
                    // privWriter.EncodeEcKey(ecdsa.Ecdsa, true);
                    var publicKey = ecdsa.Public;
                    privWriter.EncodeString(publicKey[0].ToByteArray().Reverse());
                    privWriter.EncodeString(publicKey[1].ToByteArray().Reverse());
                    privWriter.EncodeBignum2(ecdsa.Private.ToByteArray().Reverse());
                    break;
            }
            // comment
            privWriter.EncodeString(comment);

            // private key padding (1, 2, 3, ...)
            var pad = 0;
            while (privStream.Length % encryption.BlockSize != 0)
            {
                privWriter.Write((byte)++pad);
            }

            writer.EncodeString(encryption.Encrypt(privStream.GetBuffer(), 0, (int)privStream.Length));

            // Content as Base64
            var base64 = Convert.ToBase64String(stream.GetBuffer(), 0, (int)stream.Length).ToCharArray();
            var pem = new StringWriter();
            for (var i = 0; i < base64.Length; i += 70)
            {
                pem.Write(base64, i, Math.Min(70, base64.Length - i));
                pem.Write("\n");
            }

            return pem.ToString();
        }
    }
}