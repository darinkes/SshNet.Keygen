﻿using System;

namespace SshNet.Keygen.SshKeyEncryption
{
    public class SshKeyEncryptionNone : ISshKeyEncryption
    {
        public string CipherName => "none";
        public string KdfName => "none";
        public int BlockSize => 8;
        public string Passphrase => "";

        public byte[] KdfOptions()
        {
            return new byte[] { };
        }

        public byte[] Encrypt(byte[] data)
        {
            return data;
        }

        public byte[] Encrypt(byte[] data, int offset, int length)
        {
            var buffer = new byte[length];
            Buffer.BlockCopy(data, offset, buffer, 0, length);
            return Encrypt(buffer);
        }

        public byte[] PuttyEncrypt(byte[] data)
        {
            return Encrypt(data);
        }

        public byte[] PuttyEncrypt(byte[] data, int offset, int length)
        {
            return Encrypt(data, offset, length);
        }
    }
}