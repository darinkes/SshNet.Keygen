SshNet.Keygen
=============
[SSH.NET](https://github.com/sshnet/SSH.NET) Extension to generate and export Authentication Keys in OPENSSH-Format

![CodeQL](https://github.com/darinkes/SshNet.Keygen/workflows/CodeQL/badge.svg)
![.NET](https://github.com/darinkes/SshNet.Keygen/workflows/.NET/badge.svg)
[![NuGet](https://img.shields.io/nuget/v/SshNet.Keygen.svg?style=flat)](https://www.nuget.org/packages/SshNet.Keygen)
![Nuget](https://img.shields.io/nuget/dt/SshNet.Keygen)

## Status
WIP, with open ToDos and needs [MR#614](https://github.com/sshnet/SSH.NET/pull/614) merged upstream.

Currently builds it's own fork of [SSH.NET](https://github.com/sshnet/SSH.NET) to be able to automatically test them.

## Keys
* ssh-ed25519
* ecdsa-sha2-nistp256
* ecdsa-sha2-nistp384
* ecdsa-sha2-nistp521
* ssh-rsa with 2048, 3072, 4096 or 8192 KeyLength

## Fingerprinting
* Get Key Fingerprint as MD5, SHA1, SHA256, SHA384 or SHA512

## Key Encryption
* None
* AES256-ctr
* AES256-cbc

## Usage Examples

### Generate an RSA-2048 Key in File, Show the Public Key and Connect with the Private Key

```cs
SshKey.Generate("test.key");
var key = new PrivateKeyFile("test.key");
var publicKey = key.ToOpenSshPublicFormat("Generated by SshNet.Keygen");
var fingerprint = key.Fingerprint("Generated by SshNet.Keygen");

Console.WriteLine("Fingerprint: {0}", fingerprint);
Console.WriteLine("Add this to your .ssh/authorized_keys on the SSH Server: {0}", publicKey);
Console.ReadLine();

var connectionInfo = new ConnectionInfo(
    "ssh.foo.com",
    "root",
    new PrivateKeyAuthenticationMethod("root", key)
);

using (var client = new SshClient(connectionInfo))
{
    client.Connect();
    Console.WriteLine(client.RunCommand("hostname").Result);
}
```

### Generate an password protected RSA-2048 Key in File, Show the Public Key and Connect with the Private Key

```cs
SshKey.Generate("test.key", new SshKeyEncryptionAes256("12345"));
var key = new PrivateKeyFile("test.key", "12345");
var publicKey = key.ToOpenSshPublicFormat("Generated by SshNet.Keygen");
var fingerprint = key.Fingerprint("Generated by SshNet.Keygen");

Console.WriteLine("Fingerprint: {0}", fingerprint);
Console.WriteLine("Add this to your .ssh/authorized_keys on the SSH Server: {0}", publicKey);
Console.ReadLine();

var connectionInfo = new ConnectionInfo(
    "ssh.foo.com",
    "root",
    new PrivateKeyAuthenticationMethod("root", key)
);

using (var client = new SshClient(connectionInfo))
{
    client.Connect();
    Console.WriteLine(client.RunCommand("hostname").Result);
}
```

### Generate an RSA-2048 Key, Show the Public Key and Connect with the Private Key
```cs
var key = SshKey.Generate();
var publicKey = key.ToOpenSshPublicFormat("Generated by SshNet.Keygen");
var fingerprint = key.Fingerprint("Generated by SshNet.Keygen");

Console.WriteLine("Fingerprint: {0}", fingerprint);
Console.WriteLine("Add this to your .ssh/authorized_keys on the SSH Server: {0}", publicKey);
Console.ReadLine();

var connectionInfo = new ConnectionInfo(
    "ssh.foo.com",
    "root",
    new PrivateKeyAuthenticationMethod("root", key)
);

using (var client = new SshClient(connectionInfo))
{
    client.Connect();
    Console.WriteLine(client.RunCommand("hostname").Result);
}
```

### Generate an RSA-8192 Key, Show the Public Key and Connect with the Private Key
```cs
var key = SshKey.Generate<RsaKey>(8192);
var publicKey = key.ToOpenSshPublicFormat("Generated by SshNet.Keygen");
var fingerprint = key.Fingerprint("Generated by SshNet.Keygen");

Console.WriteLine("Fingerprint: {0}", fingerprint);
Console.WriteLine("Add this to your .ssh/authorized_keys on the SSH Server: {0}", publicKey);
Console.ReadLine();

var connectionInfo = new ConnectionInfo(
    "ssh.foo.com",
    "root",
    new PrivateKeyAuthenticationMethod("root", key)
);

using (var client = new SshClient(connectionInfo))
{
    client.Connect();
    Console.WriteLine(client.RunCommand("hostname").Result);
}
```

### Generate an ECDSA256 Key, Show the Public Key and Connect with the Private Key
```cs
var key = SshKey.Generate<EcdsaKey>(256);
var publicKey = key.ToOpenSshPublicFormat("Generated by SshNet.Keygen");
var fingerprint = key.Fingerprint("Generated by SshNet.Keygen");

Console.WriteLine("Fingerprint: {0}", fingerprint);
Console.WriteLine("Add this to your .ssh/authorized_keys on the SSH Server: {0}", publicKey);
Console.ReadLine();

var connectionInfo = new ConnectionInfo(
    "ssh.foo.com",
    "root",
    new PrivateKeyAuthenticationMethod("root", key)
);

using (var client = new SshClient(connectionInfo))
{
    client.Connect();
    Console.WriteLine(client.RunCommand("hostname").Result);
}
```

### Generate an ED25519 Key, Show the Public Key and Connect with the Private Key
```cs
var key = SshKey.Generate<ED25519Key>();
var publicKey = key.ToOpenSshPublicFormat("Generated by SshNet.Keygen");
var fingerprint = key.Fingerprint("Generated by SshNet.Keygen");

Console.WriteLine("Fingerprint: {0}", fingerprint);
Console.WriteLine("Add this to your .ssh/authorized_keys on the SSH Server: {0}", publicKey);
Console.ReadLine();

var connectionInfo = new ConnectionInfo(
    "ssh.foo.com",
    "root",
    new PrivateKeyAuthenticationMethod("root", key)
);

using (var client = new SshClient(connectionInfo))
{
    client.Connect();
    Console.WriteLine(client.RunCommand("hostname").Result);
}
```

### Export an existing Key from SSH.NET
```cs
var keyFile = new PrivateKeyFile("test.key");
var privateKey = keyFile.ToOpenSshFormat("Generated by SshNet.Keygen");
var publicKey = keyFile.ToOpenSshPublicFormat("Generated by SshNet.Keygen");

Console.WriteLine("Private Key: {0}", privateKey);
Console.WriteLine("Public Key: {0}", publicKey);
```