## NetCrypsi (crypsi for DotNet C#)

Custom crypto utility that wraps the DotNet `cryptography` API to make life easier

[![NetCrypsi CI](https://github.com/telkomdev/NetCrypsi/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/telkomdev/NetCrypsi/actions/workflows/ci.yml)

### NetCrypsi is compatible with each other with the following libraries
- NodeJs https://github.com/telkomdev/crypsi
- Python https://github.com/telkomdev/pycrypsi
- Golang https://github.com/telkomdev/go-crypsi
- Javascript (React and Browser) https://github.com/telkomdev/crypsi.js

### Features
- Asymmetric encryption with RSA
- Generate RSA private and public key
- Digital Signature with RSA private and public key using PSS
- Symmetric encryption with AES
- Message authentication code with HMAC
- Generate Hash with Common DIGEST Algorithm

### Add `NetCrypsi` to your project

Create new Solution
```shell
$ mkdir MyApp
$ cd MyApp/
$ dotnet new sln -n MyApp
The template "Solution File" was created successfully.
```

Create example console app inside `MyApp Solution`
```shell
$ dotnet new console -o MyApp.App
```

Add `MyApp.App` to `MyApp Solution`
```shell
$ dotnet sln MyApp.sln add MyApp.App/MyApp.App.csproj
```

Clone `NetCrypsi`
```shell
$ git clone https://github.com/telkomdev/NetCrypsi.git
```

Add `NetCrypsi.Lib` to `MyApp Solution`
```shell
$ dotnet sln MyApp.sln add NetCrypsi/NetCrypsi.Lib/NetCrypsi.Lib.csproj
```

Add Clone `NetCrypsi` to `MyApp.App` as a reference
```shell
$ dotnet add MyApp.App/MyApp.App.csproj reference NetCrypsi/NetCrypsi.Lib/NetCrypsi.Lib.csproj
```

Check MyApp reference
```shell
$ dotnet list MyApp.App/MyApp.App.csproj reference
Project reference(s)
--------------------
..\NetCrypsi\NetCrypsi.Lib\NetCrypsi.Lib.csproj
```

Edit `MyApp.App/Programm.cs`
```csharp
using System;
using System.Text;
using NetCrypsi.Lib;

// See https://aka.ms/new-console-template for more information
Console.WriteLine("Hello, World!");

Console.WriteLine(Digestx.MD5Hex(Encoding.UTF8.GetBytes("wuriyanto")));
```

Run `MyApp.App`
```shell
$ cd MyApp.App/
$ dotnet run
Hello, World!
60E1BC04FA194A343B50CE67F4AFCFF8
```