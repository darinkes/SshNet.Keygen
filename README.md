SshNet.Keygen
=============
[SSH.NET](https://github.com/sshnet/SSH.NET) Extension to generate and export Authentication Keys in OpenSSH and PuTTY v2 and v3 Format.

[![License](https://img.shields.io/github/license/darinkes/SshNet.KeyGen)](https://github.com/darinkes/SshNet.KeyGen/blob/main/LICENSE)
[![NuGet](https://img.shields.io/nuget/v/SshNet.Keygen.svg?style=flat)](https://www.nuget.org/packages/SshNet.Keygen)
![Nuget](https://img.shields.io/nuget/dt/SshNet.Keygen)

![.NET-Ubuntu](https://github.com/darinkes/SshNet.Keygen/workflows/.NET-Ubuntu/badge.svg)
![.NET-Windows](https://github.com/darinkes/SshNet.Keygen/workflows/.NET-Windows/badge.svg)
![NuGet](https://github.com/darinkes/SshNet.Keygen/workflows/NuGet/badge.svg)

## .NET Frameworks

* .NET 4.8
* netstandard 2.0

## Keys
* ssh-ed25519
* ecdsa-sha2-nistp256
* ecdsa-sha2-nistp384
* ecdsa-sha2-nistp521
* ssh-rsa with 2048, 3072, 4096 or 8192 KeyLength

## Fingerprinting
* Get Key Fingerprint as MD5, SHA1, SHA256, SHA384 or SHA512

## Key Encryption

### OpenSSH
* None
* AES256-ctr
* AES256-cbc

### PuTTY
* None
* AES256-cbc

## Usage Examples

### Generate an RSA-2048 Key in File, Show the Public Key and Connect with the Private Key

```cs
var key = SshKey.Generate("test.key", FileMode.Create);

var publicKey = key.ToPublic();
var fingerprint = key.Fingerprint();

Console.WriteLine("Fingerprint: {0}", fingerprint);
Console.WriteLine("Add this to your .ssh/authorized_keys on the SSH Server: {0}", publicKey);
Console.ReadLine();

using var client = new SshClient("ssh.foo.com", "root", key);
client.Connect();
Console.WriteLine(client.RunCommand("hostname").Result);
```

### Generate an RSA-2048 Key in PuTTY File, Show the Public Key and Connect with the Private Key

```cs
var keyInfo = new SshKeyGenerateInfo
{
    KeyFormat = SshKeyFormat.PuTTYv3
};
var key = SshKey.Generate("test.ppk", FileMode.Create, keyInfo);

var publicKey = key.ToPublic(SshKeyFormat.OpenSSH);
var fingerprint = key.Fingerprint();

Console.WriteLine("Fingerprint: {0}", fingerprint);
Console.WriteLine("Add this to your .ssh/authorized_keys on the SSH Server: {0}", publicKey);
Console.ReadLine();

using var client = new SshClient("ssh.foo.com", "root", key);
client.Connect();
Console.WriteLine(client.RunCommand("hostname").Result);
```

### Generate an password protected RSA-2048 Key in File, Show the Public Key and Connect with the Private Key

```cs
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

using var client = new SshClient("ssh.foo.com", "root", key);
client.Connect();
Console.WriteLine(client.RunCommand("hostname").Result);
```

### Generate an password protected RSA-2048 Key in Putty v2 File, Show the Public Key and Connect with the Private Key

```cs
var keyInfo = new SshKeyGenerateInfo
{
    KeyFormat = SshKeyFormat.PuTTYv2,
    Encryption = new SshKeyEncryptionAes256("12345")
};
var key = SshKey.Generate("test.ppk", FileMode.Create, keyInfo);

var publicKey = key.ToPublic(SshKeyFormat.OpenSSH);
var fingerprint = key.Fingerprint();

Console.WriteLine("Fingerprint: {0}", fingerprint);
Console.WriteLine("Add this to your .ssh/authorized_keys on the SSH Server: {0}", publicKey);
Console.ReadLine();

using var client = new SshClient("ssh.foo.com", "root", key);
client.Connect();
Console.WriteLine(client.RunCommand("hostname").Result);
```

### Generate an password protected RSA-2048 Key in Putty v3 File with own Argon Options, Show the Public Key and Connect with the Private Key

```cs
var keyInfo = new SshKeyGenerateInfo
{
    KeyFormat = SshKeyFormat.PuTTYv3,
    Encryption = new SshKeyEncryptionAes256("12345", new PuttyV3Encryption { KeyDerivation = ArgonKeyDerivation.Argon2d, Iterations = 64, DegreeOfParallelism = 44 })
};
var key = SshKey.Generate("test.ppk", FileMode.Create, keyInfo);

var publicKey = key.ToPublic(SshKeyFormat.OpenSSH);
var fingerprint = key.Fingerprint();

Console.WriteLine("Fingerprint: {0}", fingerprint);
Console.WriteLine("Add this to your .ssh/authorized_keys on the SSH Server: {0}", publicKey);
Console.ReadLine();

using var client = new SshClient("ssh.foo.com", "root", key);
client.Connect();
Console.WriteLine(client.RunCommand("hostname").Result);
```

### Generate an RSA-2048 Key, Show the Public Key and Connect with the Private Key
```cs
var key = SshKey.Generate();

var publicKey = key.ToPublic();
var fingerprint = key.Fingerprint();

Console.WriteLine("Fingerprint: {0}", fingerprint);
Console.WriteLine("Add this to your .ssh/authorized_keys on the SSH Server: {0}", publicKey);
Console.ReadLine();

using var client = new SshClient("ssh.foo.com", "root", key);
client.Connect();
Console.WriteLine(client.RunCommand("hostname").Result);
```

### Generate an RSA-8192 Key, Show the Public Key and Connect with the Private Key
```cs
var keyInfo = new SshKeyGenerateInfo
{
    KeyLength = 8192
};
var key = SshKey.Generate(keyInfo);

var publicKey = key.ToPublic();
var fingerprint = key.Fingerprint();

Console.WriteLine("Fingerprint: {0}", fingerprint);
Console.WriteLine("Add this to your .ssh/authorized_keys on the SSH Server: {0}", publicKey);
Console.ReadLine();

using var client = new SshClient("ssh.foo.com", "root", key);
client.Connect();
Console.WriteLine(client.RunCommand("hostname").Result);
```

### Generate an ECDSA-256 Key, Show the Public Key and Connect with the Private Key
```cs
var keyInfo = new SshKeyGenerateInfo(SshKeyType.ECDSA);
var key = SshKey.Generate(keyInfo);

var publicKey = key.ToPublic();
var fingerprint = key.Fingerprint();

Console.WriteLine("Fingerprint: {0}", fingerprint);
Console.WriteLine("Add this to your .ssh/authorized_keys on the SSH Server: {0}", publicKey);
Console.ReadLine();

using var client = new SshClient("ssh.foo.com", "root", key);
client.Connect();
Console.WriteLine(client.RunCommand("hostname").Result);
```

### Generate an ED25519 Key, Show the Public Key and Connect with the Private Key
```cs
var keyInfo = new SshKeyGenerateInfo(SshKeyType.ED25519);
var key = SshKey.Generate(keyInfo);

var publicKey = key.ToPublic();
var fingerprint = key.Fingerprint();

Console.WriteLine("Fingerprint: {0}", fingerprint);
Console.WriteLine("Add this to your .ssh/authorized_keys on the SSH Server: {0}", publicKey);
Console.ReadLine();

using var client = new SshClient("ssh.foo.com", "root", key);
client.Connect();
Console.WriteLine(client.RunCommand("hostname").Result);
```

### Export an existing Key from SSH.NET
```cs
var keyFile = new PrivateKeyFile("test.key");

var privateKey = keyFile.ToOpenSshFormat();
var publicKey =  keyFile.ToPublic();

Console.WriteLine("Private Key: {0}", privateKey);
Console.WriteLine("Public Key: {0}", publicKey);
```

### Export an existing Key from SSH.NET with Encryption
```cs
var keyFile = new PrivateKeyFile("test.key");

var privateKey = keyFile.ToOpenSshFormat("12345");
var puttyKey = keyFile.ToPuttyFormat("12345");
var publicKey =  keyFile.ToPublic();
var puttyPublicKey =  keyFile.ToPuttyPublicFormat();

Console.WriteLine("Private Key: {0}", privateKey);
Console.WriteLine("Putty Private Key: {0}", puttyKey);
Console.WriteLine("Public Key: {0}", publicKey);
Console.WriteLine("Putty Public Key: {0}", puttyPublicKey);
```
