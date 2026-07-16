using System;
using System.IO;
using System.Text;
using Renci.SshNet.Common;

namespace SshNet.Keygen
{
    internal class SshSignatureReader : BinaryReader
    {
        public SshSignatureReader(Stream input) : base(input, Encoding.UTF8, true)
        {
        }

        public override uint ReadUInt32()
        {
            var data = base.ReadBytes(4);
            if (data.Length < 4)
                throw new SshException("Truncated SSH signature");
            if (BitConverter.IsLittleEndian)
                Array.Reverse(data);
            return BitConverter.ToUInt32(data, 0);
        }

        public byte[] ReadStringAsBytes()
        {
            var len = ReadUInt32();
            // a length prefix must not exceed what is actually left in the buffer, or a
            // malformed signature could drive a huge up-front allocation
            var remaining = BaseStream.Length - BaseStream.Position;
            if (len > remaining)
                throw new SshException($"Declared length {len} exceeds the remaining {remaining} bytes");
            return base.ReadBytes((int)len);
        }

        public override string ReadString()
        {
            return Encoding.UTF8.GetString(ReadStringAsBytes());
        }
    }
}
