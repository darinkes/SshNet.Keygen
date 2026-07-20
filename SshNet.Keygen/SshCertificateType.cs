namespace SshNet.Keygen
{
    /// <summary>
    /// The kind of OpenSSH certificate being minted.
    /// </summary>
    public enum SshCertificateType : uint
    {
        /// <summary>A user certificate (authenticates a user to a host).</summary>
        User = 1,

        /// <summary>A host certificate (authenticates a host to a user).</summary>
        Host = 2
    }
}
