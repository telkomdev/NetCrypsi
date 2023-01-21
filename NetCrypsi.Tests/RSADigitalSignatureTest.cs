using System;
using System.Text;
using System.IO;

namespace NetCrypsi.Tests;

public class RSADigitalSignatureTest
{
    [Fact]
    public void TestGenerateRSAKeyPairsShouldSuccess()
    {
        Lib.Rsax rsax = Lib.Rsax.Create(Lib.Rsax.KeySize2Kb);
        Assert.NotNull(rsax.PrivateKeyPKCS8Bytes());
        Assert.NotNull(rsax.PrivateKeyPKCS1Bytes());
        Assert.NotNull(rsax.PublicKeyPKCS1Bytes());
    }

    [Fact]
    public void TestSignAndVerifyWithPssMD5()
    {
        Lib.Rsax rsax = Lib.Rsax.Create(Lib.Rsax.KeySize2Kb);

        byte[] publicKeyBytes;
        byte[] privateKeyBytes;

        using (FileStream publicKeyStream = File.Open("../../../testdata/public.key", FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            publicKeyBytes = Lib.Rsax.LoadKeyFromPem(publicKeyStream);
        }

        using (FileStream privateKeyStream = File.Open("../../../testdata/private_pkcs8.key", FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            privateKeyBytes = Lib.Rsax.LoadKeyFromPem(privateKeyStream);
        }

        string data = "NetCrypsi for C#";

        byte[] signature = Lib.RSADigitalSignature.SignWithPssMD5(privateKeyBytes, Encoding.UTF8.GetBytes(data));

        bool signatureValid = Lib.RSADigitalSignature.VerifySignatureWithPssMD5(publicKeyBytes, Convert.FromHexString(Convert.ToHexString(signature)), Encoding.UTF8.GetBytes(data));

        Assert.True(signatureValid);
    }

    [Fact]
    public void TestSignAndVerifyWithPssSHA1()
    {
        Lib.Rsax rsax = Lib.Rsax.Create(Lib.Rsax.KeySize2Kb);

        byte[] publicKeyBytes;
        byte[] privateKeyBytes;

        using (FileStream publicKeyStream = File.Open("../../../testdata/public.key", FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            publicKeyBytes = Lib.Rsax.LoadKeyFromPem(publicKeyStream);
        }

        using (FileStream privateKeyStream = File.Open("../../../testdata/private_pkcs8.key", FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            privateKeyBytes = Lib.Rsax.LoadKeyFromPem(privateKeyStream);
        }

        string data = "NetCrypsi for C#";

        byte[] signature = Lib.RSADigitalSignature.SignWithPssSHA1(privateKeyBytes, Encoding.UTF8.GetBytes(data));

        bool signatureValid = Lib.RSADigitalSignature.VerifySignatureWithPssSHA1(publicKeyBytes, Convert.FromHexString(Convert.ToHexString(signature)), Encoding.UTF8.GetBytes(data));

        Assert.True(signatureValid);
    }

    [Fact]
    public void TestSignAndVerifyWithPssSHA256()
    {
        Lib.Rsax rsax = Lib.Rsax.Create(Lib.Rsax.KeySize2Kb);

        byte[] publicKeyBytes;
        byte[] privateKeyBytes;

        using (FileStream publicKeyStream = File.Open("../../../testdata/public.key", FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            publicKeyBytes = Lib.Rsax.LoadKeyFromPem(publicKeyStream);
        }

        using (FileStream privateKeyStream = File.Open("../../../testdata/private_pkcs8.key", FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            privateKeyBytes = Lib.Rsax.LoadKeyFromPem(privateKeyStream);
        }

        string data = "NetCrypsi for C#";

        byte[] signature = Lib.RSADigitalSignature.SignWithPssSHA256(privateKeyBytes, Encoding.UTF8.GetBytes(data));

        bool signatureValid = Lib.RSADigitalSignature.VerifySignatureWithPssSHA256(publicKeyBytes, Convert.FromHexString(Convert.ToHexString(signature)), Encoding.UTF8.GetBytes(data));

        Assert.True(signatureValid);
    }

    [Fact]
    public void TestSignAndVerifyWithPssSHA384()
    {
        Lib.Rsax rsax = Lib.Rsax.Create(Lib.Rsax.KeySize2Kb);

        byte[] publicKeyBytes;
        byte[] privateKeyBytes;

        using (FileStream publicKeyStream = File.Open("../../../testdata/public.key", FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            publicKeyBytes = Lib.Rsax.LoadKeyFromPem(publicKeyStream);
        }

        using (FileStream privateKeyStream = File.Open("../../../testdata/private_pkcs8.key", FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            privateKeyBytes = Lib.Rsax.LoadKeyFromPem(privateKeyStream);
        }

        string data = "NetCrypsi for C#";

        byte[] signature = Lib.RSADigitalSignature.SignWithPssSHA384(privateKeyBytes, Encoding.UTF8.GetBytes(data));

        bool signatureValid = Lib.RSADigitalSignature.VerifySignatureWithPssSHA384(publicKeyBytes, Convert.FromHexString(Convert.ToHexString(signature)), Encoding.UTF8.GetBytes(data));

        Assert.True(signatureValid);
    }

    [Fact]
    public void TestSignAndVerifyWithPssSHA512()
    {
        Lib.Rsax rsax = Lib.Rsax.Create(Lib.Rsax.KeySize2Kb);

        byte[] publicKeyBytes;
        byte[] privateKeyBytes;

        using (FileStream publicKeyStream = File.Open("../../../testdata/public.key", FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            publicKeyBytes = Lib.Rsax.LoadKeyFromPem(publicKeyStream);
        }

        using (FileStream privateKeyStream = File.Open("../../../testdata/private_pkcs8.key", FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            privateKeyBytes = Lib.Rsax.LoadKeyFromPem(privateKeyStream);
        }

        string data = "NetCrypsi for C#";

        byte[] signature = Lib.RSADigitalSignature.SignWithPssSHA512(privateKeyBytes, Encoding.UTF8.GetBytes(data));

        bool signatureValid = Lib.RSADigitalSignature.VerifySignatureWithPssSHA512(publicKeyBytes, Convert.FromHexString(Convert.ToHexString(signature)), Encoding.UTF8.GetBytes(data));

        Assert.True(signatureValid);
    }

    // stream
    [Fact]
    public void TestSignAndVerifyWithPssMD5Stream()
    {
        Lib.Rsax rsax = Lib.Rsax.Create(Lib.Rsax.KeySize2Kb);

        byte[] publicKeyBytes;
        byte[] privateKeyBytes;

        using (FileStream publicKeyStream = File.Open("../../../testdata/public.key", FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            publicKeyBytes = Lib.Rsax.LoadKeyFromPem(publicKeyStream);
        }

        using (FileStream privateKeyStream = File.Open("../../../testdata/private_pkcs8.key", FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            privateKeyBytes = Lib.Rsax.LoadKeyFromPem(privateKeyStream);
        }

        byte[] signature;
        using (FileStream dataStream = File.Open("../../../testdata/burger.png", FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            signature = Lib.RSADigitalSignature.SignWithPssMD5(privateKeyBytes, dataStream);
        }

        using (FileStream dataStream = File.Open("../../../testdata/burger.png", FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            bool signatureValid = Lib.RSADigitalSignature.VerifySignatureWithPssMD5(publicKeyBytes, Convert.FromHexString(Convert.ToHexString(signature)), dataStream);
            Assert.True(signatureValid);
        }

    }

    [Fact]
    public void TestSignAndVerifyWithPssSHA1Stream()
    {
        Lib.Rsax rsax = Lib.Rsax.Create(Lib.Rsax.KeySize2Kb);

        byte[] publicKeyBytes;
        byte[] privateKeyBytes;

        using (FileStream publicKeyStream = File.Open("../../../testdata/public.key", FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            publicKeyBytes = Lib.Rsax.LoadKeyFromPem(publicKeyStream);
        }

        using (FileStream privateKeyStream = File.Open("../../../testdata/private_pkcs8.key", FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            privateKeyBytes = Lib.Rsax.LoadKeyFromPem(privateKeyStream);
        }

        byte[] signature;
        using (FileStream dataStream = File.Open("../../../testdata/burger.png", FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            signature = Lib.RSADigitalSignature.SignWithPssSHA1(privateKeyBytes, dataStream);
        }

        using (FileStream dataStream = File.Open("../../../testdata/burger.png", FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            bool signatureValid = Lib.RSADigitalSignature.VerifySignatureWithPssSHA1(publicKeyBytes, Convert.FromHexString(Convert.ToHexString(signature)), dataStream);
            Assert.True(signatureValid);
        }

    }

    [Fact]
    public void TestSignAndVerifyWithPssSHA256Stream()
    {
        Lib.Rsax rsax = Lib.Rsax.Create(Lib.Rsax.KeySize2Kb);

        byte[] publicKeyBytes;
        byte[] privateKeyBytes;

        using (FileStream publicKeyStream = File.Open("../../../testdata/public.key", FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            publicKeyBytes = Lib.Rsax.LoadKeyFromPem(publicKeyStream);
        }

        using (FileStream privateKeyStream = File.Open("../../../testdata/private_pkcs8.key", FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            privateKeyBytes = Lib.Rsax.LoadKeyFromPem(privateKeyStream);
        }

        byte[] signature;
        using (FileStream dataStream = File.Open("../../../testdata/burger.png", FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            signature = Lib.RSADigitalSignature.SignWithPssSHA256(privateKeyBytes, dataStream);
        }

        using (FileStream dataStream = File.Open("../../../testdata/burger.png", FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            bool signatureValid = Lib.RSADigitalSignature.VerifySignatureWithPssSHA256(publicKeyBytes, Convert.FromHexString(Convert.ToHexString(signature)), dataStream);
            Assert.True(signatureValid);
        }

    }

    [Fact]
    public void TestSignAndVerifyWithPssSHA384Stream()
    {
        Lib.Rsax rsax = Lib.Rsax.Create(Lib.Rsax.KeySize2Kb);

        byte[] publicKeyBytes;
        byte[] privateKeyBytes;

        using (FileStream publicKeyStream = File.Open("../../../testdata/public.key", FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            publicKeyBytes = Lib.Rsax.LoadKeyFromPem(publicKeyStream);
        }

        using (FileStream privateKeyStream = File.Open("../../../testdata/private_pkcs8.key", FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            privateKeyBytes = Lib.Rsax.LoadKeyFromPem(privateKeyStream);
        }

        byte[] signature;
        using (FileStream dataStream = File.Open("../../../testdata/burger.png", FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            signature = Lib.RSADigitalSignature.SignWithPssSHA384(privateKeyBytes, dataStream);
        }

        using (FileStream dataStream = File.Open("../../../testdata/burger.png", FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            bool signatureValid = Lib.RSADigitalSignature.VerifySignatureWithPssSHA384(publicKeyBytes, Convert.FromHexString(Convert.ToHexString(signature)), dataStream);
            Assert.True(signatureValid);
        }

    }

    [Fact]
    public void TestSignAndVerifyWithPssSHA512Stream()
    {
        Lib.Rsax rsax = Lib.Rsax.Create(Lib.Rsax.KeySize2Kb);

        byte[] publicKeyBytes;
        byte[] privateKeyBytes;

        using (FileStream publicKeyStream = File.Open("../../../testdata/public.key", FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            publicKeyBytes = Lib.Rsax.LoadKeyFromPem(publicKeyStream);
        }

        using (FileStream privateKeyStream = File.Open("../../../testdata/private_pkcs8.key", FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            privateKeyBytes = Lib.Rsax.LoadKeyFromPem(privateKeyStream);
        }

        byte[] signature;
        using (FileStream dataStream = File.Open("../../../testdata/burger.png", FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            signature = Lib.RSADigitalSignature.SignWithPssSHA512(privateKeyBytes, dataStream);
        }

        using (FileStream dataStream = File.Open("../../../testdata/burger.png", FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            bool signatureValid = Lib.RSADigitalSignature.VerifySignatureWithPssSHA512(publicKeyBytes, Convert.FromHexString(Convert.ToHexString(signature)), dataStream);
            Assert.True(signatureValid);
        }

    }
}