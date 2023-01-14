using System;
using System.Text;
using System.IO;

namespace NetCrypsi.Tests;

public class RSADigitalSignatureTest
{
    [Fact]
    public void TestGenerateRSAKeyPairsShouldSuccess()
    {
        Lib.Rsax.Rsax rsax = Lib.Rsax.Rsax.Create(Lib.Rsax.Rsax.KeySize2Kb);
        Assert.NotNull(rsax.PrivateKeyPKCS8Bytes());
        Assert.NotNull(rsax.PrivateKeyPKCS1Bytes());
        Assert.NotNull(rsax.PublicKeyPKCS1Bytes());
    }

    [Fact]
    public void TestSignAndVerifyWithPssMD5()
    {
        Lib.Rsax.Rsax rsax = Lib.Rsax.Rsax.Create(Lib.Rsax.Rsax.KeySize2Kb);

        byte[] publicKeyBytes;
        byte[] privateKeyBytes;

        using (FileStream publicKeyStream = File.Open("../../../testdata/public.key", FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            publicKeyBytes = Lib.Rsax.Rsax.LoadKeyFromPem(publicKeyStream);
        }

        using (FileStream privateKeyStream = File.Open("../../../testdata/private_pkcs8.key", FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            privateKeyBytes = Lib.Rsax.Rsax.LoadKeyFromPem(privateKeyStream);
        }

        string data = "NetCrypsi for C#";

        byte[] signature = Lib.Rsax.DigitalSignature.SignWithPssMD5(privateKeyBytes, Encoding.UTF8.GetBytes(data));

        bool signatureValid = Lib.Rsax.DigitalSignature.VerifySignatureWithPssMD5(publicKeyBytes, Convert.FromHexString(Convert.ToHexString(signature)), Encoding.UTF8.GetBytes(data));

        Assert.True(signatureValid);
    }

    [Fact]
    public void TestSignAndVerifyWithPssSHA1()
    {
        Lib.Rsax.Rsax rsax = Lib.Rsax.Rsax.Create(Lib.Rsax.Rsax.KeySize2Kb);

        byte[] publicKeyBytes;
        byte[] privateKeyBytes;

        using (FileStream publicKeyStream = File.Open("../../../testdata/public.key", FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            publicKeyBytes = Lib.Rsax.Rsax.LoadKeyFromPem(publicKeyStream);
        }

        using (FileStream privateKeyStream = File.Open("../../../testdata/private_pkcs8.key", FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            privateKeyBytes = Lib.Rsax.Rsax.LoadKeyFromPem(privateKeyStream);
        }

        string data = "NetCrypsi for C#";

        byte[] signature = Lib.Rsax.DigitalSignature.SignWithPssSHA1(privateKeyBytes, Encoding.UTF8.GetBytes(data));

        bool signatureValid = Lib.Rsax.DigitalSignature.VerifySignatureWithPssSHA1(publicKeyBytes, Convert.FromHexString(Convert.ToHexString(signature)), Encoding.UTF8.GetBytes(data));

        Assert.True(signatureValid);
    }

    [Fact]
    public void TestSignAndVerifyWithPssSHA256()
    {
        Lib.Rsax.Rsax rsax = Lib.Rsax.Rsax.Create(Lib.Rsax.Rsax.KeySize2Kb);

        byte[] publicKeyBytes;
        byte[] privateKeyBytes;

        using (FileStream publicKeyStream = File.Open("../../../testdata/public.key", FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            publicKeyBytes = Lib.Rsax.Rsax.LoadKeyFromPem(publicKeyStream);
        }

        using (FileStream privateKeyStream = File.Open("../../../testdata/private_pkcs8.key", FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            privateKeyBytes = Lib.Rsax.Rsax.LoadKeyFromPem(privateKeyStream);
        }

        string data = "NetCrypsi for C#";

        byte[] signature = Lib.Rsax.DigitalSignature.SignWithPssSHA256(privateKeyBytes, Encoding.UTF8.GetBytes(data));

        bool signatureValid = Lib.Rsax.DigitalSignature.VerifySignatureWithPssSHA256(publicKeyBytes, Convert.FromHexString(Convert.ToHexString(signature)), Encoding.UTF8.GetBytes(data));

        Assert.True(signatureValid);
    }

    [Fact]
    public void TestSignAndVerifyWithPssSHA384()
    {
        Lib.Rsax.Rsax rsax = Lib.Rsax.Rsax.Create(Lib.Rsax.Rsax.KeySize2Kb);

        byte[] publicKeyBytes;
        byte[] privateKeyBytes;

        using (FileStream publicKeyStream = File.Open("../../../testdata/public.key", FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            publicKeyBytes = Lib.Rsax.Rsax.LoadKeyFromPem(publicKeyStream);
        }

        using (FileStream privateKeyStream = File.Open("../../../testdata/private_pkcs8.key", FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            privateKeyBytes = Lib.Rsax.Rsax.LoadKeyFromPem(privateKeyStream);
        }

        string data = "NetCrypsi for C#";

        byte[] signature = Lib.Rsax.DigitalSignature.SignWithPssSHA384(privateKeyBytes, Encoding.UTF8.GetBytes(data));

        bool signatureValid = Lib.Rsax.DigitalSignature.VerifySignatureWithPssSHA384(publicKeyBytes, Convert.FromHexString(Convert.ToHexString(signature)), Encoding.UTF8.GetBytes(data));

        Assert.True(signatureValid);
    }

    [Fact]
    public void TestSignAndVerifyWithPssSHA512()
    {
        Lib.Rsax.Rsax rsax = Lib.Rsax.Rsax.Create(Lib.Rsax.Rsax.KeySize2Kb);

        byte[] publicKeyBytes;
        byte[] privateKeyBytes;

        using (FileStream publicKeyStream = File.Open("../../../testdata/public.key", FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            publicKeyBytes = Lib.Rsax.Rsax.LoadKeyFromPem(publicKeyStream);
        }

        using (FileStream privateKeyStream = File.Open("../../../testdata/private_pkcs8.key", FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            privateKeyBytes = Lib.Rsax.Rsax.LoadKeyFromPem(privateKeyStream);
        }

        string data = "NetCrypsi for C#";

        byte[] signature = Lib.Rsax.DigitalSignature.SignWithPssSHA512(privateKeyBytes, Encoding.UTF8.GetBytes(data));

        bool signatureValid = Lib.Rsax.DigitalSignature.VerifySignatureWithPssSHA512(publicKeyBytes, Convert.FromHexString(Convert.ToHexString(signature)), Encoding.UTF8.GetBytes(data));

        Assert.True(signatureValid);
    }

    // stream
    [Fact]
    public void TestSignAndVerifyWithPssMD5Stream()
    {
        Lib.Rsax.Rsax rsax = Lib.Rsax.Rsax.Create(Lib.Rsax.Rsax.KeySize2Kb);

        byte[] publicKeyBytes;
        byte[] privateKeyBytes;

        using (FileStream publicKeyStream = File.Open("../../../testdata/public.key", FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            publicKeyBytes = Lib.Rsax.Rsax.LoadKeyFromPem(publicKeyStream);
        }

        using (FileStream privateKeyStream = File.Open("../../../testdata/private_pkcs8.key", FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            privateKeyBytes = Lib.Rsax.Rsax.LoadKeyFromPem(privateKeyStream);
        }

        byte[] signature;
        using (FileStream dataStream = File.Open("../../../testdata/burger.png", FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            signature = Lib.Rsax.DigitalSignature.SignWithPssMD5(privateKeyBytes, dataStream);
        }

        using (FileStream dataStream = File.Open("../../../testdata/burger.png", FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            bool signatureValid = Lib.Rsax.DigitalSignature.VerifySignatureWithPssMD5(publicKeyBytes, Convert.FromHexString(Convert.ToHexString(signature)), dataStream);
            Assert.True(signatureValid);
        }

    }

    [Fact]
    public void TestSignAndVerifyWithPssSHA1Stream()
    {
        Lib.Rsax.Rsax rsax = Lib.Rsax.Rsax.Create(Lib.Rsax.Rsax.KeySize2Kb);

        byte[] publicKeyBytes;
        byte[] privateKeyBytes;

        using (FileStream publicKeyStream = File.Open("../../../testdata/public.key", FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            publicKeyBytes = Lib.Rsax.Rsax.LoadKeyFromPem(publicKeyStream);
        }

        using (FileStream privateKeyStream = File.Open("../../../testdata/private_pkcs8.key", FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            privateKeyBytes = Lib.Rsax.Rsax.LoadKeyFromPem(privateKeyStream);
        }

        byte[] signature;
        using (FileStream dataStream = File.Open("../../../testdata/burger.png", FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            signature = Lib.Rsax.DigitalSignature.SignWithPssSHA1(privateKeyBytes, dataStream);
        }

        using (FileStream dataStream = File.Open("../../../testdata/burger.png", FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            bool signatureValid = Lib.Rsax.DigitalSignature.VerifySignatureWithPssSHA1(publicKeyBytes, Convert.FromHexString(Convert.ToHexString(signature)), dataStream);
            Assert.True(signatureValid);
        }

    }

    [Fact]
    public void TestSignAndVerifyWithPssSHA256Stream()
    {
        Lib.Rsax.Rsax rsax = Lib.Rsax.Rsax.Create(Lib.Rsax.Rsax.KeySize2Kb);

        byte[] publicKeyBytes;
        byte[] privateKeyBytes;

        using (FileStream publicKeyStream = File.Open("../../../testdata/public.key", FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            publicKeyBytes = Lib.Rsax.Rsax.LoadKeyFromPem(publicKeyStream);
        }

        using (FileStream privateKeyStream = File.Open("../../../testdata/private_pkcs8.key", FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            privateKeyBytes = Lib.Rsax.Rsax.LoadKeyFromPem(privateKeyStream);
        }

        byte[] signature;
        using (FileStream dataStream = File.Open("../../../testdata/burger.png", FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            signature = Lib.Rsax.DigitalSignature.SignWithPssSHA256(privateKeyBytes, dataStream);
        }

        using (FileStream dataStream = File.Open("../../../testdata/burger.png", FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            bool signatureValid = Lib.Rsax.DigitalSignature.VerifySignatureWithPssSHA256(publicKeyBytes, Convert.FromHexString(Convert.ToHexString(signature)), dataStream);
            Assert.True(signatureValid);
        }

    }

    [Fact]
    public void TestSignAndVerifyWithPssSHA384Stream()
    {
        Lib.Rsax.Rsax rsax = Lib.Rsax.Rsax.Create(Lib.Rsax.Rsax.KeySize2Kb);

        byte[] publicKeyBytes;
        byte[] privateKeyBytes;

        using (FileStream publicKeyStream = File.Open("../../../testdata/public.key", FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            publicKeyBytes = Lib.Rsax.Rsax.LoadKeyFromPem(publicKeyStream);
        }

        using (FileStream privateKeyStream = File.Open("../../../testdata/private_pkcs8.key", FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            privateKeyBytes = Lib.Rsax.Rsax.LoadKeyFromPem(privateKeyStream);
        }

        byte[] signature;
        using (FileStream dataStream = File.Open("../../../testdata/burger.png", FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            signature = Lib.Rsax.DigitalSignature.SignWithPssSHA384(privateKeyBytes, dataStream);
        }

        using (FileStream dataStream = File.Open("../../../testdata/burger.png", FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            bool signatureValid = Lib.Rsax.DigitalSignature.VerifySignatureWithPssSHA384(publicKeyBytes, Convert.FromHexString(Convert.ToHexString(signature)), dataStream);
            Assert.True(signatureValid);
        }

    }

    [Fact]
    public void TestSignAndVerifyWithPssSHA512Stream()
    {
        Lib.Rsax.Rsax rsax = Lib.Rsax.Rsax.Create(Lib.Rsax.Rsax.KeySize2Kb);

        byte[] publicKeyBytes;
        byte[] privateKeyBytes;

        using (FileStream publicKeyStream = File.Open("../../../testdata/public.key", FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            publicKeyBytes = Lib.Rsax.Rsax.LoadKeyFromPem(publicKeyStream);
        }

        using (FileStream privateKeyStream = File.Open("../../../testdata/private_pkcs8.key", FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            privateKeyBytes = Lib.Rsax.Rsax.LoadKeyFromPem(privateKeyStream);
        }

        byte[] signature;
        using (FileStream dataStream = File.Open("../../../testdata/burger.png", FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            signature = Lib.Rsax.DigitalSignature.SignWithPssSHA512(privateKeyBytes, dataStream);
        }

        using (FileStream dataStream = File.Open("../../../testdata/burger.png", FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            bool signatureValid = Lib.Rsax.DigitalSignature.VerifySignatureWithPssSHA512(publicKeyBytes, Convert.FromHexString(Convert.ToHexString(signature)), dataStream);
            Assert.True(signatureValid);
        }

    }
}