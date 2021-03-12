SshNet.PuttyKey
=============
[SSH.NET](https://github.com/sshnet/SSH.NET) Extension to read and use Authentication Keys in PuTTY-Format

[![License](https://img.shields.io/github/license/darinkes/SshNet.PuttyKey)](https://github.com/darinkes/SshNet.PuttyKey/blob/main/LICENSE)

![CodeQL](https://github.com/darinkes/SshNet.PuttyKey/workflows/CodeQL/badge.svg)
![.NET-Ubuntu](https://github.com/darinkes/SshNet.PuttyKey/workflows/.NET-Ubuntu/badge.svg)
![.NET-Windows](https://github.com/darinkes/SshNet.PuttyKey/workflows/.NET-Windows/badge.svg)

## Status
WIP

Currently builds it's own fork of [SSH.NET](https://github.com/sshnet/SSH.NET) to be able to automatically test them.

Needs this Branch: https://github.com/darinkes/SSH.NET-1/tree/agent_auth

## .NET Frameworks

* .NET 4.0
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
var key = PuttyKey.Open("my-key.ppk");

using var client = new SshClient("ssh.foo.com", "root", key);
client.Connect();
Console.WriteLine(client.RunCommand("hostname").Result);
```
