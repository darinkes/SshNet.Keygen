namespace SshNet.Keygen.SshKeyEncryption
{
    public enum ArgonKeyDerivation
    {
        Argon2d,
        Argon2i,
        Argon2id
    }

    public class PuttyV3Encryption
    {
        internal byte[]? Result;
        internal byte[] MacKey;
        internal byte[]? Salt;

        public ArgonKeyDerivation KeyDerivation = ArgonKeyDerivation.Argon2id;
        public int DegreeOfParallelism = 1;
        public int MemorySize = 8192;
        public int Iterations = 22;

        public PuttyV3Encryption()
        {
            MacKey = new byte[0];
        }
    }
}