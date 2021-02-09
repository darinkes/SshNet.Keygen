namespace SshNet.Keygen.SshKeyEncryption
{
    public interface ISshKeyEncryption
    {
        public string CipherName { get; }

        public string KdfName { get; }

        public int BlockSize { get; }

        public byte[] KdfOptions();

        public byte[] Encrypt(byte[] data);

        public byte[] Encrypt(byte[] data, int offset, int length);
    }
}