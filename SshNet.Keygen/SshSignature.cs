using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Renci.SshNet.Common;
using Renci.SshNet.Security;
using Renci.SshNet.Security.Cryptography;
using SshNet.Keygen.Extensions;

namespace SshNet.Keygen
{
    /// <summary>
    /// Creates and verifies detached SSH signatures (the SSHSIG format produced by
    /// <c>ssh-keygen -Y sign</c> and checked by <c>ssh-keygen -Y verify</c>).
    /// </summary>
    public class SshSignature
    {
        private static readonly Regex SshSignatureRegex = new(
            "^-+ *BEGIN SSH SIGNATURE *-+(\\r|\\n)*(?<data>([a-zA-Z0-9/+=]{1,80}(\\r|\\n)+)+)(\\r|\\n)*-+ *END SSH SIGNATURE *-+",
            RegexOptions.Compiled | RegexOptions.Multiline);

        private static readonly string Preambel = "SSHSIG";
        private static readonly uint Version = 1;

        /// <summary>Verifies the SSHSIG signature in <paramref name="signaturePath"/> against the contents of <paramref name="path"/>.</summary>
        /// <param name="path">The signed file.</param>
        /// <param name="signaturePath">The armored signature file (usually <c>&lt;path&gt;.sig</c>).</param>
        /// <param name="namespace">The namespace the signature must be bound to (OpenSSH's <c>-n</c>).</param>
        /// <returns><see langword="true"/> if the signature is valid for the file. See the remarks on <see cref="Verify(byte[], string, string)"/> about signer identity.</returns>
        public static bool VerifyFile(string path, string signaturePath, string @namespace = "file")
        {
            return Verify(File.ReadAllBytes(path), File.ReadAllText(signaturePath), @namespace);
        }

        /// <summary>Verifies the signature file and that it was produced by <paramref name="expectedSigner"/>.</summary>
        /// <param name="path">The signed file.</param>
        /// <param name="signaturePath">The armored signature file (usually <c>&lt;path&gt;.sig</c>).</param>
        /// <param name="expectedSigner">The public key the signature must have been made with.</param>
        /// <param name="namespace">The namespace the signature must be bound to.</param>
        /// <returns><see langword="true"/> if the signature is valid, in the given namespace, and made by <paramref name="expectedSigner"/>.</returns>
        public static bool VerifyFile(string path, string signaturePath, Key expectedSigner, string @namespace = "file")
        {
            return Verify(File.ReadAllBytes(path), File.ReadAllText(signaturePath), expectedSigner, @namespace);
        }

        /// <summary>Verifies an armored SSHSIG <paramref name="signature"/> against <paramref name="data"/>.</summary>
        /// <remarks>
        /// A <see langword="true"/> result only proves the signature is internally consistent - that
        /// whoever holds the private key for the public key embedded in the signature signed the data
        /// in this namespace. It does NOT establish that a <em>trusted</em> party signed it. To
        /// authenticate the signer, use the <see cref="Verify(byte[], string, Key, string)"/> overload
        /// with a key you trust, or the <c>out</c> overload and check the returned key yourself.
        /// </remarks>
        /// <param name="data">The signed data.</param>
        /// <param name="signature">The armored SSH signature (<c>-----BEGIN SSH SIGNATURE-----</c> block).</param>
        /// <param name="namespace">The namespace the signature must be bound to (OpenSSH's <c>-n</c>).</param>
        /// <returns><see langword="true"/> if the signature is valid for the data and namespace.</returns>
        public static bool Verify(byte[] data, string signature, string @namespace = "file")
        {
            return VerifyInternal(data, signature, @namespace, out _, out _);
        }

        /// <summary>
        /// Verifies the signature and returns the public key that produced it, so the caller can
        /// check it against a trusted set. See the remarks on <see cref="Verify(byte[], string, string)"/>.
        /// </summary>
        /// <param name="data">The signed data.</param>
        /// <param name="signature">The armored SSH signature.</param>
        /// <param name="signer">The public key embedded in the signature.</param>
        /// <param name="namespace">The namespace the signature must be bound to.</param>
        /// <returns><see langword="true"/> if the signature is valid for the data and namespace.</returns>
        public static bool Verify(byte[] data, string signature, out Key signer, string @namespace = "file")
        {
            return VerifyInternal(data, signature, @namespace, out signer, out _);
        }

        /// <summary>
        /// Verifies the signature and that it was produced by <paramref name="expectedSigner"/> - i.e.
        /// authenticates the signer against a key you already trust.
        /// </summary>
        /// <param name="data">The signed data.</param>
        /// <param name="signature">The armored SSH signature.</param>
        /// <param name="expectedSigner">The public key the signature must have been made with.</param>
        /// <param name="namespace">The namespace the signature must be bound to.</param>
        /// <returns><see langword="true"/> if the signature is valid, in the given namespace, and made by <paramref name="expectedSigner"/>.</returns>
        public static bool Verify(byte[] data, string signature, Key expectedSigner, string @namespace = "file")
        {
            if (!VerifyInternal(data, signature, @namespace, out _, out var signerBlob))
                return false;
            return PublicKeyBlob(expectedSigner).SequenceEqual(signerBlob);
        }

        private static byte[] PublicKeyBlob(Key key)
        {
            using var stream = new MemoryStream();
            using var writer = new BinaryWriter(stream);
            key.PublicKeyData(writer);
            return stream.ToArray();
        }

        private static bool VerifyInternal(byte[] data, string signature, string @namespace, out Key signer, out byte[] signerBlob)
        {
            signer = null!;
            signerBlob = null!;

            var signatureMatch = SshSignatureRegex.Match(signature);
            if (!signatureMatch.Success)
                throw new SshException("Invalid SSH signature");

            byte[] binaryData;
            try
            {
                binaryData = Convert.FromBase64String(signatureMatch.Result("${data}"));
            }
            catch (FormatException e)
            {
                throw new SshException("Invalid SSH signature base64", e);
            }

            using var stream = new MemoryStream(binaryData);
            using var reader = new SshSignatureReader(stream);

            if (Encoding.ASCII.GetString(reader.ReadBytes(6)) != Preambel)
                throw new SshException("Wrong preamble");

            if (reader.ReadUInt32() != Version)
                throw new SshException("Wrong version");

            signerBlob = reader.ReadStringAsBytes(); // public key
            var sigNamespace = reader.ReadString();
            reader.ReadString(); // reserved (read and ignored, like OpenSSH)
            var hashAlgo = reader.ReadString();

            using var hashAlgorithm = CreateHash(hashAlgo);

            var encodedSignature = reader.ReadStringAsBytes();
            using var signatureStream = new MemoryStream(encodedSignature);
            using var signatureReader = new SshSignatureReader(signatureStream);

            var sigAlgo = signatureReader.ReadString();
            var sigData = signatureReader.ReadStringAsBytes();

            DigitalSignature digitalSignature;
            switch (sigAlgo)
            {
                case "rsa-sha2-512":
                    signer = new RsaKey(new SshKeyData(signerBlob));
                    digitalSignature = new RsaDigitalSignature((RsaKey)signer, HashAlgorithmName.SHA512);
                    break;
                case "rsa-sha2-256":
                    signer = new RsaKey(new SshKeyData(signerBlob));
                    digitalSignature = new RsaDigitalSignature((RsaKey)signer, HashAlgorithmName.SHA256);
                    break;
                case "ssh-ed25519":
                    signer = new ED25519Key(new SshKeyData(signerBlob));
                    digitalSignature = new ED25519DigitalSignature((ED25519Key)signer);
                    break;
                case "ecdsa-sha2-nistp256":
                case "ecdsa-sha2-nistp384":
                case "ecdsa-sha2-nistp521":
                    signer = new EcdsaKey(new SshKeyData(signerBlob));
                    digitalSignature = new EcdsaDigitalSignature((EcdsaKey)signer);
                    break;
                default:
                    throw new SshException($"Unknown signature algorithm {sigAlgo}");
            }

            // a signature bound to another namespace must not verify in this one
            if (sigNamespace != @namespace)
                return false;

            using var verifyStream = new MemoryStream();
            using var verifyWriter = new BinaryWriter(verifyStream);
            verifyWriter.Write(Encoding.UTF8.GetBytes(Preambel));
            verifyWriter.EncodeBinary(sigNamespace);
            verifyWriter.EncodeBinary(""); // reserved
            verifyWriter.EncodeBinary(hashAlgo);
            verifyWriter.EncodeBinary(hashAlgorithm.ComputeHash(data));

            return digitalSignature.Verify(verifyStream.ToArray(), sigData);
        }

        // SSHSIG permits only sha256 and sha512; reject weaker platform hashes an attacker could name
        private static HashAlgorithm CreateHash(string hashAlgo)
        {
            switch (hashAlgo)
            {
                case "sha256":
                    return SHA256.Create();
                case "sha512":
                    return SHA512.Create();
                default:
                    throw new SshException($"Unsupported hash algorithm {hashAlgo}");
            }
        }

        internal static void SignatureFile(KeyHostAlgorithm keyHostAlgorithm, string path, string @namespace = "file")
        {
            var sigFile = $"{path}.sig";
            File.WriteAllText(sigFile, Signature(keyHostAlgorithm, File.ReadAllBytes(path), @namespace));
        }

        internal static string Signature(KeyHostAlgorithm keyHostAlgorithm, byte[] data, string @namespace = "file")
        {
            const string hashAlgo = "sha512";

            using var pubStream = new MemoryStream();
            using var pubWriter = new BinaryWriter(pubStream);
            keyHostAlgorithm.Key.PublicKeyData(pubWriter);

            using var hashAlgorithm = SHA512.Create();

            using var signStream = new MemoryStream();
            using var signWriter = new BinaryWriter(signStream);
            signWriter.Write(Encoding.UTF8.GetBytes(Preambel));
            signWriter.EncodeBinary(@namespace);
            signWriter.EncodeBinary(""); // reserved
            signWriter.EncodeBinary(hashAlgo);
            signWriter.EncodeBinary(hashAlgorithm.ComputeHash(data));
            var signed = keyHostAlgorithm.Sign(signStream.ToArray());

            using var stream = new MemoryStream();
            using var writer = new BinaryWriter(stream);
            writer.Write(Encoding.UTF8.GetBytes(Preambel));
            writer.EncodeUInt(Version);
            writer.EncodeBinary(pubStream.ToArray());
            writer.EncodeBinary(@namespace);
            writer.EncodeBinary(""); // reserved
            writer.EncodeBinary(hashAlgo);
            writer.EncodeBinary(signed);

            var base64 = Convert.ToBase64String(stream.ToArray()).ToCharArray();
            using var pem = new StringWriter();
            for (var i = 0; i < base64.Length; i += 70)
            {
                pem.Write(base64, i, Math.Min(70, base64.Length - i));
                pem.Write("\n");
            }

            using var s = new StringWriter();
            s.Write("-----BEGIN SSH SIGNATURE-----\n");
            s.Write(pem.ToString());
            s.Write("-----END SSH SIGNATURE-----\n");
            return s.ToString();
        }
    }
}