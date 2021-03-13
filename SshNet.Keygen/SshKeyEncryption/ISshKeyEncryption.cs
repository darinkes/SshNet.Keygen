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

        public byte[] PuttyEncrypt(byte[] data);

        public byte[] PuttyEncrypt(byte[] data, int offset, int length);
    }
}