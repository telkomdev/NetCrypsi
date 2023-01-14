using System;
using System.Text;
using System.IO;

namespace NetCrypsi.Tests;

public class RSAEncryptionTest
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
    public void TestEncryptAndDecryptWithOaepMD5()
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

        byte[] encryptedData = Lib.Rsax.Encryption.EncryptWithOaepMD5(publicKeyBytes, Encoding.UTF8.GetBytes(data));

        byte[] decryptedData = Lib.Rsax.Encryption.DecryptWithOaepMD5(privateKeyBytes, Convert.FromBase64String(Convert.ToBase64String(encryptedData)));

        Assert.Equal(data, Encoding.UTF8.GetString(decryptedData));
    }

    [Fact]
    public void TestEncryptAndDecryptWithOaepSHA1()
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

        byte[] encryptedData = Lib.Rsax.Encryption.EncryptWithOaepSHA1(publicKeyBytes, Encoding.UTF8.GetBytes(data));

        byte[] decryptedData = Lib.Rsax.Encryption.DecryptWithOaepSHA1(privateKeyBytes, Convert.FromBase64String(Convert.ToBase64String(encryptedData)));

        Assert.Equal(data, Encoding.UTF8.GetString(decryptedData));
    }

    [Fact]
    public void TestEncryptAndDecryptWithOaepSHA256()
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

        byte[] encryptedData = Lib.Rsax.Encryption.EncryptWithOaepSHA256(publicKeyBytes, Encoding.UTF8.GetBytes(data));

        byte[] decryptedData = Lib.Rsax.Encryption.DecryptWithOaepSHA256(privateKeyBytes, Convert.FromBase64String(Convert.ToBase64String(encryptedData)));

        Assert.Equal(data, Encoding.UTF8.GetString(decryptedData));
    }

    [Fact]
    public void TestEncryptAndDecryptWithOaepSHA384()
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

        byte[] encryptedData = Lib.Rsax.Encryption.EncryptWithOaepSHA384(publicKeyBytes, Encoding.UTF8.GetBytes(data));

        byte[] decryptedData = Lib.Rsax.Encryption.DecryptWithOaepSHA384(privateKeyBytes, Convert.FromBase64String(Convert.ToBase64String(encryptedData)));

        Assert.Equal(data, Encoding.UTF8.GetString(decryptedData));
    }

    [Fact]
    public void TestEncryptAndDecryptWithOaepSHA512()
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

        byte[] encryptedData = Lib.Rsax.Encryption.EncryptWithOaepSHA512(publicKeyBytes, Encoding.UTF8.GetBytes(data));

        byte[] decryptedData = Lib.Rsax.Encryption.DecryptWithOaepSHA512(privateKeyBytes, Convert.FromBase64String(Convert.ToBase64String(encryptedData)));

        Assert.Equal(data, Encoding.UTF8.GetString(decryptedData));
    }
}