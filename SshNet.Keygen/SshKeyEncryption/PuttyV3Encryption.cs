namespace SshNet.Keygen.SshKeyEncryption
{
    /// <summary>
    /// The Argon2 variant used to derive the encryption key for a PuTTY v3 key file.
    /// </summary>
    public enum ArgonKeyDerivation
    {
        /// <summary>Argon2d (data-dependent).</summary>
        Argon2d,

        /// <summary>Argon2i (data-independent).</summary>
        Argon2i,

        /// <summary>Argon2id (hybrid, recommended default).</summary>
        Argon2id
    }

    /// <summary>
    /// Argon2 parameters for PuTTY v3 key encryption.
    /// </summary>
    public class PuttyV3Encryption
    {
        internal byte[]? Result;
        internal byte[] MacKey;
        internal byte[]? Salt;

        /// <summary>The Argon2 variant to use. Defaults to <see cref="ArgonKeyDerivation.Argon2id"/>.</summary>
        public ArgonKeyDerivation KeyDerivation = ArgonKeyDerivation.Argon2id;

        /// <summary>Argon2 degree of parallelism (lanes). Defaults to <c>1</c>.</summary>
        public int DegreeOfParallelism = 1;

        /// <summary>Argon2 memory size in kibibytes. Defaults to <c>8192</c>.</summary>
        public int MemorySize = 8192;

        /// <summary>Argon2 iteration (pass) count. Defaults to <c>22</c>.</summary>
        public int Iterations = 22;

        /// <summary>Initializes a new instance with the default Argon2id parameters.</summary>
        public PuttyV3Encryption()
        {
            MacKey = new byte[0];
        }
    }
}
