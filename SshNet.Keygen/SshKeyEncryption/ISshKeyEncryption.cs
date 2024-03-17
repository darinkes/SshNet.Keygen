namespace SshNet.Keygen.SshKeyEncryption
{
    public interface ISshKeyEncryption
    {
        public string CipherName { get; }

        public string KdfName { get; }

        public int BlockSize { get; }

        public string Passphrase { get; }

        public byte[] KdfOptions();

        public byte[] Encrypt(byte[] data);

        public byte[] Encrypt(byte[] data, int offset, int length);

        public byte[] PuttyV2Encrypt(byte[] data);

        public byte[] PuttyV2Encrypt(byte[] data, int offset, int length);

        public PuttyV3Encryption PuttyV3Encrypt(byte[] data);

        public PuttyV3Encryption PuttyV3Encrypt(byte[] data, int offset, int length);
    }
}