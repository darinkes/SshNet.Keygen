using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Renci.SshNet;
using Renci.SshNet.Security;

namespace SshNet.Keygen.Extensions
{
    public static class KeyExtension
    {
        public static string ToOpenSshFormat(this PrivateKeyFile keyFile, string comment = "")
        {
            return ((KeyHostAlgorithm) keyFile.HostKey).Key.ToOpenSshFormat(comment);
        }

        public static string ToOpenSshPublicFormat(this PrivateKeyFile keyFile, string comment = "")
        {
            return ((KeyHostAlgorithm) keyFile.HostKey).Key.ToOpenSshPublicFormat(comment);
        }

        public static string Fingerprint(this PrivateKeyFile keyFile, string comment = "")
        {
            return keyFile.Fingerprint(HashAlgorithmName.SHA256, comment);
        }

        public static string Fingerprint(this PrivateKeyFile keyFile, HashAlgorithmName hashAlgorithm,  string comment = "")
        {
            return ((KeyHostAlgorithm) keyFile.HostKey).Key.Fingerprint(hashAlgorithm, comment);
        }

        public static string ToOpenSshFormat(this Key key, string comment = "")
        {
            var s = new StringWriter();
            s.Write("-----BEGIN OPENSSH PRIVATE KEY-----\n");
            s.Write(key.KeyData(comment));
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

        public static string Fingerprint(this Key key, HashAlgorithmName hashAlgorithm, string comment = "")
        {
            // SHA256 of PublicKey-Data
            using var pubStream = new MemoryStream();
            using var pubWriter = new BinaryWriter(pubStream);
            key.PublicKeyData(pubWriter);
            byte[] pubKeyHash;

            using (var hash = HashAlgorithm.Create(hashAlgorithm.Name))
            {
                if (hash == null)
                    throw new CryptographicException($"Unsupported HashAlgorithmName: {hashAlgorithm.Name}");
                pubKeyHash = hash.ComputeHash(pubStream.GetBuffer(), 0, (int)pubStream.Length);
            }

            // base64 without padding or Hex
            var base64 = hashAlgorithm == HashAlgorithmName.MD5 ?
                BitConverter.ToString(pubKeyHash).ToLower().Replace('-', ':') :
                Convert.ToBase64String(pubKeyHash, 0, (int)pubKeyHash.Length).TrimEnd('=');

            return $"{key.KeyLength} {hashAlgorithm.Name}:{base64} {comment} ({key.KeyName()})";
        }

        private static string KeyName(this Key key)
        {
            switch (key)
            {
                case ED25519Key:
                    return "ED25519";
                case RsaKey:
                    return "RSA";
                case EcdsaKey:
                    return "ECDSA";
            }

            throw new Exception("Unknown KeyType");
        }

        private static void PublicKeyData(this Key key, BinaryWriter writer)
        {
            EncodeString(writer, key.ToString());
            switch (key)
            {
                case ED25519Key ed25519:
                    EncodeBignum2(writer, ed25519.PublicKey);
                    break;
                case RsaKey rsa:
                    EncodeBignum2(writer, rsa.Exponent.ToByteArray().Reverse());
                    EncodeBignum2(writer, rsa.Modulus.ToByteArray().Reverse());
                    break;
                case EcdsaKey ecdsa:
                    EncodeEcKey(writer, ecdsa.Ecdsa, false);
                    break;
            }
        }

        private static string KeyData(this Key key, string comment)
        {
            using var stream = new MemoryStream();
            using var writer = new BinaryWriter(stream);

            EncodeNullTerminatedString(writer,"openssh-key-v1"); // Auth Magic
            EncodeString(writer, "none"); // cipher name
            EncodeString(writer, "none"); // kdf name
            EncodeString(writer, ""); // kdf options
            EncodeUInt(writer, 1); // Number of Keys

            // public key in ssh-format
            using var pubStream = new MemoryStream();
            using var pubWriter = new BinaryWriter(pubStream);
            key.PublicKeyData(pubWriter);
            EncodeString(writer, pubStream);

            // private key
            using var privStream = new MemoryStream();
            using var privWriter = new BinaryWriter(privStream);

            var rnd = new Random().Next(0, int.MaxValue);
            EncodeInt(privWriter, rnd); // check-int1
            EncodeInt(privWriter, rnd); // check-int2
            EncodeString(privWriter, key.ToString());
            switch (key)
            {
                case ED25519Key ed25519:
                    EncodeBignum2(privWriter, ed25519.PublicKey);
                    EncodeBignum2(privWriter, ed25519.PrivateKey);
                    break;
                case RsaKey rsa:
                    EncodeBignum2(privWriter, rsa.Modulus.ToByteArray().Reverse());
                    EncodeBignum2(privWriter, rsa.Exponent.ToByteArray().Reverse());
                    EncodeBignum2(privWriter, rsa.D.ToByteArray().Reverse());
                    EncodeBignum2(privWriter, rsa.InverseQ.ToByteArray().Reverse());
                    EncodeBignum2(privWriter, rsa.P.ToByteArray().Reverse());
                    EncodeBignum2(privWriter, rsa.Q.ToByteArray().Reverse());
                    break;
                case EcdsaKey ecdsa:
                    EncodeEcKey(privWriter, ecdsa.Ecdsa, true);
                    break;
            }
            // comment
            EncodeString(privWriter, comment);

            // private key padding (1, 2, 3, ...)
            var pad = 0;
            while (privStream.Length % 8 != 0)
            {
                privWriter.Write((byte)++pad);
            }
            EncodeString(writer, privStream);

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

        private static void EncodeEcKey(BinaryWriter writer, ECDsa ecdsa, bool includePrivate)
        {
            var ecdsaParameters = ecdsa.ExportParameters(includePrivate);
            var q = new byte[1 + ecdsaParameters.Q.X.Length + ecdsaParameters.Q.Y.Length];
            Buffer.SetByte(q, 0, 4); // Uncompressed
            Buffer.BlockCopy(ecdsaParameters.Q.X, 0, q, 1, ecdsaParameters.Q.X.Length);
            Buffer.BlockCopy(ecdsaParameters.Q.Y, 0, q, ecdsaParameters.Q.X.Length + 1, ecdsaParameters.Q.Y.Length);

            EncodeString(writer, ecdsa.EcCurveNameSshCompat());
            EncodeString(writer, q);
            if (includePrivate)
                EncodeBignum2(writer, ecdsaParameters.D);
        }

        private static void EncodeNullTerminatedString(BinaryWriter writer, string str)
        {
            writer.Write(Encoding.ASCII.GetBytes(str));
            writer.Write('\0');
        }

        private static void EncodeString(BinaryWriter writer, string str)
        {
            EncodeString(writer, Encoding.ASCII.GetBytes(str));
        }

        private static void EncodeString(BinaryWriter writer, MemoryStream str)
        {
            EncodeString(writer, str.GetBuffer(), 0, (int)str.Length);
        }

        private static void EncodeString(BinaryWriter writer, byte[] str)
        {
            EncodeUInt(writer, (uint)str.Length);
            writer.Write(str);
        }

        private static void EncodeString(BinaryWriter writer, byte[] str, int offset, int length)
        {
            EncodeUInt(writer, (uint)length);
            writer.Write(str, offset, length);
        }

        private static void EncodeBignum2(BinaryWriter writer, byte[] data)
        {
            EncodeUInt(writer, (uint)data.Length);
            writer.Write(data);
        }

        private static void EncodeUInt(BinaryWriter writer, uint i)
        {
            var data = BitConverter.GetBytes(i);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(data);
            writer.Write(data);
        }

        private static void EncodeInt(BinaryWriter writer, int i)
        {
            var data = BitConverter.GetBytes(i);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(data);
            writer.Write(data);
        }
    }
}