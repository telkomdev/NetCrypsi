using System;
using System.Text;
using System.IO;

namespace NetCrypsi.Tests;

public class RSATest
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
    public void TestLoadPrivateAndPublicKeyFromPEMFile()
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

        Assert.NotNull(publicKeyBytes);
        Assert.NotNull(privateKeyBytes);
    }

    [Fact]
    public void TestRSAXCreateShouldThrowsExceptionWhenKeyIsInvalid()
    {
        Assert.Throws<ArgumentException>(() => Lib.Rsax.Create(512));
    }
}