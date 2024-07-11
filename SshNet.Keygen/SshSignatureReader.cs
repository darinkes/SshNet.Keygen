using System;
using System.IO;
using System.Text;

namespace SshNet.Keygen
{
    public class SshSignatureReader : BinaryReader
    {
        public SshSignatureReader(Stream input) : base(input, Encoding.Default, true)
        {
        }

        public override uint ReadUInt32()
        {
            var data = base.ReadBytes(4);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(data);
            return BitConverter.ToUInt32(data, 0);
        }

        public byte[] ReadStringAsBytes()
        {
            var len = (int)ReadUInt32();
            return base.ReadBytes(len);
        }

        public override string ReadString()
        {
            return Encoding.UTF8.GetString(ReadStringAsBytes());
        }
    }
}