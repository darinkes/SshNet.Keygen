using System;
using Renci.SshNet.Common;

namespace SshNet.PuttyKey.Extensions
{
    internal static class ByteExtension
    {
        public static T[] Reverse<T>(this T[] array)
        {
            Array.Reverse(array);
            return array;
        }

        public static byte[] TrimLeadingZeros(this byte[] value)
        {
            if (value == null)
                throw new ArgumentNullException(nameof(value));

            for (var i = 0; i < value.Length; i++)
            {
                if (value[i] == 0)
                    continue;

                // if the first byte is non-zero, then we return the byte array as is
                if (i == 0)
                    return value;

                var remainingBytes = value.Length - i;

                var cleaned = new byte[remainingBytes];
                Buffer.BlockCopy(value, i, cleaned, 0, remainingBytes);
                return cleaned;
            }

            return value;
        }
    }
}