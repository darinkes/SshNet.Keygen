using System.Text;

namespace SshNet.Keygen.Extensions
{
    internal static class StringExtension
    {
        internal static string FormatNewLines(this string str, int count)
        {
            var sb = new StringBuilder(str);
            for (var i = count; i < sb.Length; i+=count+1)
            {
                sb.Insert(i, "\n");
            }
            return sb.ToString();
        }
    }
}