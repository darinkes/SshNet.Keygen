using System;
using System.IO;
using Renci.SshNet;
using SshNet.Keygen.Extensions;
using SshNet.Keygen.SshKeyEncryption;

namespace SshNet.Keygen.Sample
{
    class Program
    {
        static void Main(string[] args)
        {
            var keyInfo = new SshKeyGenerateInfo
            {
                Encryption = new SshKeyEncryptionAes256("12345")
            };
            var key = SshKey.Generate("test.key", FileMode.Create, keyInfo);

            var publicKey = key.ToPublic();
            var fingerprint = key.Fingerprint();

            Console.WriteLine("Fingerprint: {0}", fingerprint);
            Console.WriteLine("Add this to your .ssh/authorized_keys on the SSH Server: {0}", publicKey);
            Console.ReadLine();

            using var client = new SshClient("localhost", Environment.GetEnvironmentVariable("USER") ?? Environment.GetEnvironmentVariable("USERNAME"), key);
            client.Connect();
            Console.WriteLine(client.RunCommand("hostname").Result);
        }
    }
}