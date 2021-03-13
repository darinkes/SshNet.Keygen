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
            var key = SshKey.Generate("test.key", FileMode.Create,
                new SshKeyEncryptionAes256("12345"),
                $"{Environment.UserName}@{Environment.MachineName}"
            );
            var publicKey = key.ToOpenSshPublicFormat();
            var fingerprint = key.Fingerprint();

            Console.WriteLine("Fingerprint: {0}", fingerprint);
            Console.WriteLine("Add this to your .ssh/authorized_keys of the SSH Server: {0}", publicKey);
            Console.ReadLine();

            using var client = new SshClient("ssh.foo.com", "root", key);
            client.Connect();
            Console.WriteLine(client.RunCommand("hostname").Result);
        }
    }
}