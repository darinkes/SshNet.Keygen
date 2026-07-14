namespace SshNet.Keygen
{
    /// <summary>
    /// The on-disk format a key is written in.
    /// </summary>
    public enum SshKeyFormat
    {
        /// <summary>OpenSSH private key format.</summary>
        OpenSSH,

        /// <summary>PuTTY private key format, version 2.</summary>
        PuTTYv2,

        /// <summary>PuTTY private key format, version 3.</summary>
        PuTTYv3,
    }
}
