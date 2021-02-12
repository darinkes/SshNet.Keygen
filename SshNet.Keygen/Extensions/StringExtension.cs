using System.IO;

namespace SshNet.Keygen.Extensions
{
    internal static class StringExtension
    {
        internal static Stream ToStream(this string s)
        {
            var stream = new MemoryStream();
            var writer = new StreamWriter(stream);
            writer.Write(s);
            writer.Flush();
            stream.Position = 0;
            return stream;
        }
    }
}