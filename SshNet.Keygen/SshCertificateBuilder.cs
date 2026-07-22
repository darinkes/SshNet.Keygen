using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using Renci.SshNet;
using Renci.SshNet.Security;
using Renci.SshNet.Security.Cryptography;
using SshNet.Keygen.Extensions;

namespace SshNet.Keygen
{
    /// <summary>
    /// Fluent builder that mints and signs an OpenSSH certificate (the <c>ssh-keygen -s</c> step).
    /// </summary>
    public class SshCertificateBuilder
    {
        // OpenSSH's default user-certificate extensions (all flag-only, empty data).
        private static readonly string[] DefaultUserExtensionNames =
        {
            "permit-X11-forwarding", "permit-agent-forwarding", "permit-port-forwarding",
            "permit-pty", "permit-user-rc"
        };

        private readonly Key _publicKey;
        private ulong _serial;
        private SshCertificateType _type = SshCertificateType.User;
        private string _keyId = "";
        private readonly List<string> _principals = new();
        private ulong _validAfter;
        private ulong _validBefore = ulong.MaxValue;
        private readonly SortedDictionary<string, string> _criticalOptions = new(StringComparer.Ordinal);
        private readonly SortedDictionary<string, string> _extensions = new(StringComparer.Ordinal);
        private bool _extensionsSet;
        private byte[]? _nonce;

        /// <summary>Starts a certificate for the given public key to certify.</summary>
        /// <param name="publicKey">The key to certify (only its public part is used).</param>
        public SshCertificateBuilder(Key publicKey)
        {
            _publicKey = publicKey ?? throw new ArgumentNullException(nameof(publicKey));
        }

        /// <summary>Starts a certificate for the public key of the given source.</summary>
        /// <param name="publicKey">The key source to certify.</param>
        public SshCertificateBuilder(IPrivateKeySource publicKey) : this(KeyOf(publicKey))
        {
        }

        /// <summary>Sets the certificate serial number.</summary>
        /// <param name="serial">The serial number.</param>
        public SshCertificateBuilder WithSerial(ulong serial)
        {
            _serial = serial;
            return this;
        }

        /// <summary>Sets the certificate type (user or host).</summary>
        /// <param name="type">The certificate type.</param>
        public SshCertificateBuilder WithType(SshCertificateType type)
        {
            _type = type;
            return this;
        }

        /// <summary>Sets the key id (a human-readable label recorded in the certificate).</summary>
        /// <param name="keyId">The key id.</param>
        public SshCertificateBuilder WithKeyId(string keyId)
        {
            _keyId = keyId ?? "";
            return this;
        }

        /// <summary>Adds a valid principal (a username for user certs, a hostname for host certs).</summary>
        /// <param name="principal">The principal.</param>
        public SshCertificateBuilder WithPrincipal(string principal)
        {
            _principals.Add(principal);
            return this;
        }

        /// <summary>Adds valid principals. An empty set means the certificate is valid for all principals.</summary>
        /// <param name="principals">The principals.</param>
        public SshCertificateBuilder WithPrincipals(IEnumerable<string> principals)
        {
            _principals.AddRange(principals);
            return this;
        }

        /// <summary>Sets the validity window.</summary>
        /// <param name="validAfter">Not valid before this time.</param>
        /// <param name="validBefore">Not valid after this time.</param>
        public SshCertificateBuilder WithValidity(DateTime validAfter, DateTime validBefore)
        {
            if (validAfter > validBefore)
                throw new ArgumentException("validAfter must not be later than validBefore.", nameof(validAfter));
            _validAfter = ToUnixSeconds(validAfter);
            _validBefore = ToUnixSeconds(validBefore);
            return this;
        }

        /// <summary>Marks the certificate valid forever (the default).</summary>
        public SshCertificateBuilder ValidForever()
        {
            _validAfter = 0;
            _validBefore = ulong.MaxValue;
            return this;
        }

        /// <summary>Adds a critical option (e.g. <c>force-command</c>, <c>source-address</c>).</summary>
        /// <param name="name">The option name.</param>
        /// <param name="data">The option value.</param>
        public SshCertificateBuilder WithCriticalOption(string name, string data)
        {
            _criticalOptions[name] = data ?? "";
            return this;
        }

        /// <summary>Adds an extension. Setting any extension replaces the default user extensions.</summary>
        /// <param name="name">The extension name.</param>
        /// <param name="data">The extension value (empty for flag extensions).</param>
        public SshCertificateBuilder WithExtension(string name, string data = "")
        {
            _extensionsSet = true;
            _extensions[name] = data ?? "";
            return this;
        }

        /// <summary>Sets the certificate nonce. If unset, 32 random bytes are generated.</summary>
        /// <param name="nonce">The nonce.</param>
        public SshCertificateBuilder WithNonce(byte[] nonce)
        {
            if (nonce is null || nonce.Length == 0)
                throw new ArgumentException("Nonce must not be null or empty.", nameof(nonce));
            _nonce = nonce;
            return this;
        }

        /// <summary>Signs the certificate with the given CA key source.</summary>
        /// <param name="caKey">The CA key source (must hold a private key).</param>
        public SshCertificate SignWith(IPrivateKeySource caKey)
        {
            return SignWith(KeyOf(caKey));
        }

        /// <summary>Signs the certificate with the given CA key.</summary>
        /// <param name="caKey">The CA key (must hold a private key).</param>
        public SshCertificate SignWith(Key caKey)
        {
            if (caKey is null)
                throw new ArgumentNullException(nameof(caKey));

            return Sign(CaHostAlgorithm(caKey));
        }

        /// <summary>
        /// Signs the certificate with the given CA host algorithm. Use this when the CA private key
        /// lives outside the process — in a TPM or HSM — and cannot be handed over as a <see cref="Key"/>:
        /// the algorithm carries the signer, so the key is never exported. Pass, for example, the first
        /// entry of an <see cref="IPrivateKeySource.HostKeyAlgorithms"/> backed by such a signer.
        /// </summary>
        /// <param name="caAlgorithm">The CA host algorithm; its key and signer sign the certificate.</param>
        public SshCertificate SignWith(KeyHostAlgorithm caAlgorithm)
        {
            if (caAlgorithm is null)
                throw new ArgumentNullException(nameof(caAlgorithm));

            return Sign(caAlgorithm);
        }

        private SshCertificate Sign(KeyHostAlgorithm ca)
        {
            var typeName = $"{_publicKey}-cert-v01@openssh.com";
            var nonce = _nonce ?? RandomBytes(32);

            using var stream = new MemoryStream();
            using var writer = new BinaryWriter(stream);

            writer.EncodeBinary(typeName);
            writer.EncodeBinary(nonce);
            _publicKey.PublicKeyFields(writer);           // type-specific public fields of the certified key
            writer.EncodeUInt64(_serial);
            writer.EncodeUInt((uint)_type);
            writer.EncodeBinary(_keyId);
            writer.EncodeBinary(EncodeStrings(_principals));
            writer.EncodeUInt64(_validAfter);
            writer.EncodeUInt64(_validBefore);
            writer.EncodeBinary(EncodeOptions(_criticalOptions));
            writer.EncodeBinary(EncodeOptions(EffectiveExtensions()));
            writer.EncodeBinary("");                      // reserved
            writer.EncodeBinary(PublicKeyBlob(ca.Key));   // signature key: CA public key blob

            // signature over everything serialized so far
            var signature = ca.Sign(stream.ToArray());
            writer.EncodeBinary(signature);

            var comment = string.IsNullOrEmpty(_publicKey.Comment) ? _keyId : _publicKey.Comment;
            return new SshCertificate(typeName, stream.ToArray(), PublicKeyBlob(_publicKey), comment);
        }

        private SortedDictionary<string, string> EffectiveExtensions()
        {
            if (_extensionsSet || _type != SshCertificateType.User)
                return _extensions;

            var defaults = new SortedDictionary<string, string>(StringComparer.Ordinal);
            foreach (var name in DefaultUserExtensionNames)
                defaults[name] = "";
            return defaults;
        }

        private static KeyHostAlgorithm CaHostAlgorithm(Key caKey)
        {
            // OpenSSH signs certificates with an RSA CA using rsa-sha2-512; other key types use their native algorithm.
            if (caKey is RsaKey rsaKey)
                return new KeyHostAlgorithm("rsa-sha2-512", caKey, new RsaDigitalSignature(rsaKey, HashAlgorithmName.SHA512));
            return new KeyHostAlgorithm(caKey.ToString(), caKey);
        }

        private static byte[] PublicKeyBlob(Key key)
        {
            using var stream = new MemoryStream();
            using var writer = new BinaryWriter(stream);
            key.PublicKeyData(writer);
            return stream.ToArray();
        }

        // A sequence of SSH strings, concatenated (used for the principals list).
        private static byte[] EncodeStrings(IEnumerable<string> items)
        {
            using var stream = new MemoryStream();
            using var writer = new BinaryWriter(stream);
            foreach (var item in items)
                writer.EncodeBinary(item);
            return stream.ToArray();
        }

        // A sequence of (name, data) pairs. Flag options carry an empty data string; valued options
        // wrap their value in an inner SSH string, per PROTOCOL.certkeys.
        private static byte[] EncodeOptions(SortedDictionary<string, string> options)
        {
            using var stream = new MemoryStream();
            using var writer = new BinaryWriter(stream);
            foreach (var option in options)
            {
                writer.EncodeBinary(option.Key);
                if (string.IsNullOrEmpty(option.Value))
                {
                    writer.EncodeBinary("");
                }
                else
                {
                    using var inner = new MemoryStream();
                    using var innerWriter = new BinaryWriter(inner);
                    innerWriter.EncodeBinary(option.Value);
                    writer.EncodeBinary(inner.ToArray());
                }
            }
            return stream.ToArray();
        }

        private static Key KeyOf(IPrivateKeySource source)
        {
            return ((KeyHostAlgorithm)source.HostKeyAlgorithms.First()).Key;
        }

        private static byte[] RandomBytes(int count)
        {
            var bytes = new byte[count];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(bytes);
            return bytes;
        }

        private static ulong ToUnixSeconds(DateTime dt)
        {
            var seconds = new DateTimeOffset(dt.ToUniversalTime()).ToUnixTimeSeconds();
            return seconds < 0 ? 0 : (ulong)seconds;
        }
    }
}
