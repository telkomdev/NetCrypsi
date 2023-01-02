using System;
using System.Text;
using System.IO;

namespace NetCrypsi.Tests;

public class RSATest
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
    public void TestLoadPrivateAndPublicKeyFromPEMFile()
    {
        Lib.Rsax.Rsax rsax = Lib.Rsax.Rsax.Create(Lib.Rsax.Rsax.KeySize2Kb);

        byte[] publicKeyBytes;
        byte[] privateKeyBytes;

        using (FileStream publicKeyStream = File.Open("../../../testdata/public.key", FileMode.Open))
        {
            publicKeyBytes = Lib.Rsax.Rsax.LoadKeyFromPem(publicKeyStream);
        }

        using (FileStream privateKeyStream = File.Open("../../../testdata/private_pkcs8.key", FileMode.Open))
        {
            privateKeyBytes = Lib.Rsax.Rsax.LoadKeyFromPem(privateKeyStream);
        }

        Assert.NotNull(publicKeyBytes);
        Assert.NotNull(privateKeyBytes);
    }

    [Fact]
    public void TestRSAXCreateShouldThrowsExceptionWhenKeyIsInvalid()
    {
        Assert.Throws<ArgumentException>(() => Lib.Rsax.Rsax.Create(512));
    }
}