using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Renci.SshNet.Common;
using Renci.SshNet.Security;
using Renci.SshNet.Security.Cryptography;
using SshNet.Keygen.Extensions;

namespace SshNet.Keygen
{
    public class SshSignature
    {
        private static readonly Regex SshSignatureRegex = new(
            "^-+ *BEGIN SSH SIGNATURE *-+(\\r|\\n)*(?<data>([a-zA-Z0-9/+=]{1,80}(\\r|\\n)+)+)(\\r|\\n)*-+ *END SSH SIGNATURE *-+",
            RegexOptions.Compiled | RegexOptions.Multiline);

        private static readonly string Preambel = "SSHSIG";
        private static readonly uint Version = 1;

        public static bool VerifyFile(string path, string signaturePath)
        {
            return Verify(File.ReadAllBytes(path), File.ReadAllText(signaturePath));
        }

        public static bool Verify(byte[] data, string signature)
        {
            var signatureMatch = SshSignatureRegex.Match(signature);
            if (!signatureMatch.Success)
            {
                throw new SshException("Invalid SSH signature");
            }

            var signatureData = signatureMatch.Result("${data}");
            var binaryData = Convert.FromBase64String(signatureData);

            var stream = new MemoryStream(binaryData);
            var reader = new SshSignatureReader(stream);

            if (Encoding.ASCII.GetString(reader.ReadBytes(6)) != Preambel)
                throw new SshException("Wrong preamble");

            if (reader.ReadUInt32() != Version)
                throw new SshException("Wrong version");

            var pubKeyLength = reader.ReadUInt32(); // pub key length
            var pubKeyData = reader.ReadBytes((int)pubKeyLength); // pubkey

            var @namespace = reader.ReadString(); // namespace
            reader.ReadString(); // reserved
            var hashAlgo = reader.ReadString(); // hash-algo
            var hashAlgorithm = HashAlgorithm.Create(hashAlgo);

            if (hashAlgorithm is null)
                throw new SshException($"Unknown hash algorithm {hashAlgo}");

            var encodedSignatureLength = reader.ReadUInt32();
            var encodedSignature = reader.ReadBytes((int)encodedSignatureLength);
            var signatureStream = new MemoryStream(encodedSignature);
            var signatureReader = new SshSignatureReader(signatureStream);

            var sigAlgo = signatureReader.ReadString(); // sig algo
            var sigLength = signatureReader.ReadUInt32(); // sig length
            var sigData = signatureReader.ReadBytes((int)sigLength); // sig

            DigitalSignature digitalSignature;
            Key key;

            switch (sigAlgo)
            {
                case "rsa-sha2-512":
                    key = new RsaKey(new SshKeyData(pubKeyData));
                    digitalSignature = new RsaDigitalSignature((RsaKey)key, HashAlgorithmName.SHA512);
                    break;
                case "rsa-sha2-256":
                    key = new RsaKey(new SshKeyData(pubKeyData));
                    digitalSignature = new RsaDigitalSignature((RsaKey)key, HashAlgorithmName.SHA256);
                    break;
                case "ssh-ed25519":
                    key = new ED25519Key(new SshKeyData(pubKeyData));
                    digitalSignature = new ED25519DigitalSignature((ED25519Key)key);
                    break;
                case "ecdsa-sha2-nistp256":
                case "ecdsa-sha2-nistp384":
                case "ecdsa-sha2-nistp521":
                    key = new EcdsaKey(new SshKeyData(pubKeyData));
                    digitalSignature = new EcdsaDigitalSignature((EcdsaKey)key);
                    break;
                default:
                    throw new SshException($"Unknown signature algorithm {sigAlgo}");
            }

            var verifyStream = new MemoryStream();
            var verifyWriter = new BinaryWriter(verifyStream);
            verifyWriter.Write(Encoding.UTF8.GetBytes(Preambel));
            verifyWriter.EncodeBinary(@namespace);
            verifyWriter.EncodeBinary(""); // reserved
            verifyWriter.EncodeBinary(hashAlgo);
            verifyWriter.EncodeBinary(hashAlgorithm.ComputeHash(data));

            return digitalSignature.Verify(verifyStream.ToArray(), sigData);
        }

        public static void SignatureFile(KeyHostAlgorithm keyHostAlgorithm, string path)
        {
            var sigFile = $"{path}.sig";
            File.WriteAllText(sigFile, Signature(keyHostAlgorithm, File.ReadAllBytes(path)));
        }

        public static string Signature(KeyHostAlgorithm keyHostAlgorithm, byte[] data)
        {
            var hashAlgorithmName = HashAlgorithmName.SHA512;
            var @namespace = "file";  // ToDo: expose?

            using var pubStream = new MemoryStream();
            using var pubWriter = new BinaryWriter(pubStream);
            keyHostAlgorithm.Key.PublicKeyData(pubWriter);

            var hashAlgorithm = HashAlgorithm.Create(hashAlgorithmName.Name);
            if (hashAlgorithm is null)
                throw new SshException($"Unknown hash algorithm {hashAlgorithmName.Name}");

            var signStream = new MemoryStream();
            var signWriter = new BinaryWriter(signStream);
            signWriter.Write(Encoding.UTF8.GetBytes(Preambel));
            signWriter.EncodeBinary(@namespace);
            signWriter.EncodeBinary(""); // reserved
            signWriter.EncodeBinary(hashAlgorithmName.Name.ToLower());
            signWriter.EncodeBinary(hashAlgorithm.ComputeHash(data));
            var signed = keyHostAlgorithm.Sign(signStream.ToArray());

            var stream = new MemoryStream();
            var writer = new BinaryWriter(stream);

            writer.Write(Encoding.UTF8.GetBytes(Preambel));
            writer.EncodeUInt(Version);
            writer.EncodeBinary(pubStream.ToArray());
            writer.EncodeBinary(@namespace);
            writer.EncodeBinary(""); // reserved
            writer.EncodeBinary(hashAlgorithmName.Name.ToLower());
            writer.EncodeBinary(signed);

            var base64 = Convert.ToBase64String(stream.ToArray()).ToCharArray();
            var pem = new StringWriter();
            for (var i = 0; i < base64.Length; i += 70)
            {
                pem.Write(base64, i, Math.Min(70, base64.Length - i));
                pem.Write("\n");
            }

            var s = new StringWriter();
            s.Write($"-----BEGIN SSH SIGNATURE-----\n");
            s.Write(pem.ToString());
            s.Write("-----END SSH SIGNATURE-----\n");
            return s.ToString();
        }
    }
}