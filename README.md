SshNet.PuttyKeyFile
=============
[SSH.NET](https://github.com/sshnet/SSH.NET) Extension to read and use Authentication Keys in PuTTY-Format

[![License](https://img.shields.io/github/license/darinkes/SshNet.PuttyKeyFile)](https://github.com/darinkes/SshNet.PuttyKeyFile/blob/main/LICENSE)
[![NuGet](https://img.shields.io/nuget/v/SshNet.PuttyKeyFile.svg?style=flat)](https://www.nuget.org/packages/SshNet.PuttyKeyFile)
![Nuget](https://img.shields.io/nuget/dt/SshNet.PuttyKeyFile)

![CodeQL](https://github.com/darinkes/SshNet.PuttyKeyFile/workflows/CodeQL/badge.svg)
![.NET-Ubuntu](https://github.com/darinkes/SshNet.PuttyKeyFile/workflows/.NET-Ubuntu/badge.svg)
![.NET-Windows](https://github.com/darinkes/SshNet.PuttyKeyFile/workflows/.NET-Windows/badge.svg)
![NuGet](https://github.com/darinkes/SshNet.PuttyKeyFile/workflows/NuGet/badge.svg)

## Status
WIP

## .NET Frameworks

* .NET 4.6
* netstandard 2.0

## Keys
* ssh-ed25519
* ecdsa-sha2-nistp256
* ecdsa-sha2-nistp384
* ecdsa-sha2-nistp521
* ssh-rsa with 2048, 3072, 4096 or 8192 KeyLength

## Key Encryption
* None
* AES256-cbc

## Usage Example

```cs
var key = new PuttyKeyFile("my-key.ppk");

using var client = new SshClient("ssh.foo.com", "root", key);
client.Connect();
Console.WriteLine(client.RunCommand("hostname").Result);
```