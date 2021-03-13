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
            return key.Fingerprint(SshKey.DefaultHashAlgorithmName);
        }

        public static string Fingerprint(this Key key, SshKeyHashAlgorithmName hashAlgorithm)
        {
            using var pubStream = new MemoryStream();
            using var pubWriter = new BinaryWriter(pubStream);
            key.PublicKeyData(pubWriter);
            byte[] pubKeyHash;

            using (var hash = SshKeyHashAlgorithm.Create(hashAlgorithm))
            {
                pubKeyHash = hash.ComputeHash(pubStream.GetBuffer(), 0, (int)pubStream.Length);
            }

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
            var base64 = Convert.ToBase64String(pubStream.GetBuffer(), 0, (int)pubStream.Length);
            return $"{key} {base64} {key.Comment ?? ""}\n";
        }

        #endregion

        #region OpenSshFormat

        public static string ToOpenSshFormat(this Key key)
        {
            return key.ToOpenSshFormat(SshKey.DefaultSshKeyEncryption);
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
                    var publicKey = ecdsa.Public;
                    privWriter.EncodeString(publicKey[0].ToByteArray().Reverse());
                    privWriter.EncodeString(publicKey[1].ToByteArray().Reverse());
                    privWriter.EncodeBignum2(ecdsa.PrivateKey.ToBigInteger2().ToByteArray().Reverse());
                    break;
                default:
                    throw new NotSupportedException($"Unsupported KeyType: {key}");
            }
            // comment
            privWriter.EncodeString(key.Comment ?? "");

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

        #endregion

        #region PuttyFormat

        public static string ToPuttyFormat(this Key key)
        {
            return key.ToPuttyFormat(SshKey.DefaultSshKeyEncryption);
        }

        public static string ToPuttyFormat(this Key key, ISshKeyEncryption encryption)
        {
            // Public Key
            using var pubStream = new MemoryStream();
            using var pubWriter = new BinaryWriter(pubStream);
            key.PublicKeyData(pubWriter);

            var publicBase64String = Convert.ToBase64String(pubStream.GetBuffer(), 0, (int) pubStream.Length).FormatNewLines(64);

            // Private Key
            using var privStream = new MemoryStream();
            using var privWriter = new BinaryWriter(privStream);
            switch (key.ToString())
            {
                case "ssh-ed25519":
                    var ed25519 = (ED25519Key)key;
                    privWriter.EncodeBignum2(ed25519.PrivateKey);
                    break;
                case "ssh-rsa":
                    var rsa = (RsaKey)key;
                    privWriter.EncodeBignum2(rsa.D.ToByteArray().Reverse());
                    privWriter.EncodeBignum2(rsa.P.ToByteArray().Reverse());
                    privWriter.EncodeBignum2(rsa.Q.ToByteArray().Reverse());
                    privWriter.EncodeBignum2(rsa.InverseQ.ToByteArray().Reverse());
                    break;
                case "ecdsa-sha2-nistp256":
                    // Fallthrough
                case "ecdsa-sha2-nistp384":
                    // Fallthrough
                case "ecdsa-sha2-nistp521":
                    var ecdsa = (EcdsaKey)key;
                    privWriter.EncodeBignum2(ecdsa.PrivateKey.ToBigInteger2().ToByteArray().Reverse());
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

            var encrypted = encryption.PuttyEncrypt(privStream.GetBuffer(), 0, (int)privStream.Length);
            var privateBase64String = Convert.ToBase64String(encrypted).FormatNewLines(64);

            // MAC
            using var macStream = new MemoryStream();
            using var macWriter = new BinaryWriter(macStream);
            macWriter.EncodeString(key.ToString());
            macWriter.EncodeString(encryption.CipherName);
            macWriter.EncodeString(key.Comment ?? "");
            macWriter.EncodeString(pubStream.GetBuffer(), 0, (int) pubStream.Length);
            macWriter.EncodeString(privStream.GetBuffer(), 0, (int) privStream.Length);

            var hashData = new byte[macStream.Length];
            Buffer.BlockCopy(macStream.GetBuffer(), 0, hashData, 0, (int) macStream.Length);

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
                    var publicKey = ecdsa.Public;
                    writer.EncodeString(publicKey[0].ToByteArray().Reverse());
                    writer.EncodeString(publicKey[1].ToByteArray().Reverse());
                    break;
                default:
                    throw new NotSupportedException($"Unsupported KeyType: {key}");
            }
        }
    }
}