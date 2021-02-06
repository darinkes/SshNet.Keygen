using System.IO;

namespace SshNet.Keygen.Tests
{
    public static class StringExtensions
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