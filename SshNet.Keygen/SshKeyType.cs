namespace SshNet.Keygen
{
    /// <summary>
    /// The asymmetric key algorithm to generate.
    /// </summary>
    public enum SshKeyType
    {
        /// <summary>RSA key.</summary>
        RSA,

        /// <summary>ECDSA (NIST curve) key.</summary>
        ECDSA,

        /// <summary>Ed25519 key.</summary>
        ED25519
    }
}
