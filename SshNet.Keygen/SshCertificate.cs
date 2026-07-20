using System;
using System.Security.Cryptography;

namespace SshNet.Keygen
{
    /// <summary>
    /// A signed OpenSSH certificate produced by <see cref="SshCertificateBuilder"/>.
    /// </summary>
    public class SshCertificate
    {
        /// <summary>The certificate wire blob (the base64-encoded part of a *-cert-v01 line).</summary>
        public byte[] Blob { get; }

        /// <summary>The certificate type name, e.g. <c>ssh-ed25519-cert-v01@openssh.com</c>.</summary>
        public string TypeName { get; }

        /// <summary>The trailing comment used on the public certificate line.</summary>
        public string Comment { get; }

        private readonly byte[] _publicKeyBlob;

        internal SshCertificate(string typeName, byte[] blob, byte[] publicKeyBlob, string comment)
        {
            TypeName = typeName;
            Blob = blob;
            _publicKeyBlob = publicKeyBlob;
            Comment = comment;
        }

        /// <summary>The certificate wire blob.</summary>
        public byte[] ToByteArray()
        {
            return Blob;
        }

        /// <summary>The public certificate line: <c>&lt;type&gt; &lt;base64(blob)&gt; &lt;comment&gt;</c>.</summary>
        public string ToOpenSshPublicFormat()
        {
            return $"{TypeName} {Convert.ToBase64String(Blob)} {Comment}\n";
        }

        /// <summary>
        /// The SHA256 fingerprint (<c>SHA256:...</c>) of the certified public key, matching
        /// what <c>ssh-keygen -l</c> reports for the certificate.
        /// </summary>
        public string Fingerprint()
        {
            using var sha256 = SHA256.Create();
            var hash = sha256.ComputeHash(_publicKeyBlob);
            return $"SHA256:{Convert.ToBase64String(hash).TrimEnd('=')}";
        }
    }
}
