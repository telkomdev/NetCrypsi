using System;
using System.IO;
using System.Text;

namespace NetCrypsi.Tests;

public class AESTest
{
    private readonly string key128Str = "kJjG$qMCzbzqW6WW";

    private readonly string key192Str = "kJjG$qMCzbzqW6WWge2ZHFD7";

    private readonly string key256Str = "kJjG$qMCzbzqW6WWge2ZHFD777gjERHO";

    // AES CBC Encrypt and Decrypt Bytes
    [Fact]
    public void TestEncryptBytesDataWithAES128CBCShouldEqualToDecryptedData()
    {
        string expected = "wuriyanto";

        byte[] encryptedData = Lib.Aesx.EncryptWithAES128CBC(Encoding.UTF8.GetBytes(expected), Encoding.UTF8.GetBytes(key128Str));
        byte[] decryptedData = Lib.Aesx.DecryptWithAES128CBC(encryptedData, Encoding.UTF8.GetBytes(key128Str));

        string actual = Encoding.UTF8.GetString(decryptedData);
        Assert.Equal(expected, actual);
    }

    [Fact]
    public void TestEncryptBytesDataWithAES192CBCShouldEqualToDecryptedData()
    {
        string expected = "wuriyanto";

        byte[] encryptedData = Lib.Aesx.EncryptWithAES192CBC(Encoding.UTF8.GetBytes(expected), Encoding.UTF8.GetBytes(key192Str));
        byte[] decryptedData = Lib.Aesx.DecryptWithAES192CBC(encryptedData, Encoding.UTF8.GetBytes(key192Str));

        string actual = Encoding.UTF8.GetString(decryptedData);
        Assert.Equal(expected, actual);
    }

    [Fact]
    public void TestEncryptBytesDataWithAES256CBCShouldEqualToDecryptedData()
    {
        string expected = "wuriyanto";

        byte[] encryptedData = Lib.Aesx.EncryptWithAES256CBC(Encoding.UTF8.GetBytes(expected), Encoding.UTF8.GetBytes(key256Str));
        byte[] decryptedData = Lib.Aesx.DecryptWithAES256CBC(encryptedData, Encoding.UTF8.GetBytes(key256Str));

        string actual = Encoding.UTF8.GetString(decryptedData);
        Assert.Equal(expected, actual);
    }

    [Fact]
    public void TestDecryptEmptyBytesDataWithAES256CBCShouldEqualToDecryptedData()
    {
        string expected = "";

        byte[] decryptedData = Lib.Aesx.DecryptWithAES256CBC(Encoding.UTF8.GetBytes("91d67cce84b7a189d178697ef78fc9b4059b61b33004dc33d9be139afadd0660"), Encoding.UTF8.GetBytes(key256Str));

        string actual = Encoding.UTF8.GetString(decryptedData);
        Assert.Equal(expected, actual);
    }

    // AES CBC Encrypt and Decrypt IO Stream
    [Fact]
    public void TestEncryptStreamDataWithAES128CBCShouldEqualToDecryptedData()
    {
        using (FileStream streamInput = File.Open("../../../testdata/burger.png", FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            using (MemoryStream streamEncryptedOutput = new MemoryStream())
            {
                Lib.Aesx.EncryptWithAES128CBC(streamInput, streamEncryptedOutput, Encoding.UTF8.GetBytes(key128Str));

                using (MemoryStream streamDecryptedOutput = new MemoryStream())
                {
                    Lib.Aesx.DecryptWithAES128CBC(streamEncryptedOutput, streamDecryptedOutput, Encoding.UTF8.GetBytes(key128Str));

                    // check if two HASH values of the original input Stream and the resultant Stream of decryption are equal
                    string expected = Lib.Digestx.SHA1Hex(streamInput);
                    string actual = Lib.Digestx.SHA1Hex(streamDecryptedOutput);

                    Assert.Equal(expected, actual);
                }
            }
        }
    }

    [Fact]
    public void TestEncryptStreamDataWithAES192CBCShouldEqualToDecryptedData()
    {
        using (FileStream streamInput = File.Open("../../../testdata/burger.png", FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            using (MemoryStream streamEncryptedOutput = new MemoryStream())
            {
                Lib.Aesx.EncryptWithAES192CBC(streamInput, streamEncryptedOutput, Encoding.UTF8.GetBytes(key192Str));

                using (MemoryStream streamDecryptedOutput = new MemoryStream())
                {
                    Lib.Aesx.DecryptWithAES192CBC(streamEncryptedOutput, streamDecryptedOutput, Encoding.UTF8.GetBytes(key192Str));

                    // check if two HASH values of the original input Stream and the resultant Stream of decryption are equal
                    string expected = Lib.Digestx.SHA1Hex(streamInput);
                    string actual = Lib.Digestx.SHA1Hex(streamDecryptedOutput);

                    Assert.Equal(expected, actual);
                }
            }
        }
    }

    [Fact]
    public void TestEncryptStreamDataWithAES256CBCShouldEqualToDecryptedData()
    {
        using (FileStream streamInput = File.Open("../../../testdata/burger.png", FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            using (MemoryStream streamEncryptedOutput = new MemoryStream())
            {
                Lib.Aesx.EncryptWithAES256CBC(streamInput, streamEncryptedOutput, Encoding.UTF8.GetBytes(key256Str));

                using (MemoryStream streamDecryptedOutput = new MemoryStream())
                {
                    Lib.Aesx.DecryptWithAES256CBC(streamEncryptedOutput, streamDecryptedOutput, Encoding.UTF8.GetBytes(key256Str));

                    // check if two HASH values of the original input Stream and the resultant Stream of decryption are equal
                    string expected = Lib.Digestx.SHA1Hex(streamInput);
                    string actual = Lib.Digestx.SHA1Hex(streamDecryptedOutput);

                    Assert.Equal(expected, actual);
                }
            }
        }
    }

    // Test throw exception
    [Fact]
    public void TestEncryptBytesDataWithAES128CBCShouldThrowArgumentNullExceptionWhenDataIsNull()
    {
        string expected = "wuriyanto";

        Assert.Throws<ArgumentNullException>(() => Lib.Aesx.EncryptWithAES128CBC(null, Encoding.UTF8.GetBytes(key128Str)));
    }

    [Fact]
    public void TestEncryptBytesDataWithAES128CBCShouldThrowArgumentNullExceptionWhenKeyIsNull()
    {
        string expected = "wuriyanto";

        Assert.Throws<ArgumentNullException>(() => Lib.Aesx.EncryptWithAES128CBC(Encoding.UTF8.GetBytes(expected), null));
    }

    [Fact]
    public void TestEncryptBytesDataWithAES128CBCShouldThrowArgumentNullExceptionWhenKeyIsEmpty()
    {
        string expected = "wuriyanto";

        Assert.Throws<ArgumentNullException>(() => Lib.Aesx.EncryptWithAES128CBC(Encoding.UTF8.GetBytes(expected), Encoding.UTF8.GetBytes("")));
    }

    // AES GCM Encrypt and Decrypt Bytes
    [Fact]
    public void TestEncryptBytesDataWithAES128GCMShouldEqualToDecryptedData()
    {
        string expected = "wuriyanto";

        byte[] encryptedData = Lib.Aesx.EncryptWithAES128GCM(Encoding.UTF8.GetBytes(expected), Encoding.UTF8.GetBytes(key128Str));
        byte[] decryptedData = Lib.Aesx.DecryptWithAES128GCM(encryptedData, Encoding.UTF8.GetBytes(key128Str));

        string actual = Encoding.UTF8.GetString(decryptedData);
        Assert.Equal(expected, actual);
    }

    [Fact]
    public void TestEncryptBytesDataWithAES192GCMShouldEqualToDecryptedData()
    {
        string expected = "wuriyanto";

        byte[] encryptedData = Lib.Aesx.EncryptWithAES192GCM(Encoding.UTF8.GetBytes(expected), Encoding.UTF8.GetBytes(key192Str));
        byte[] decryptedData = Lib.Aesx.DecryptWithAES192GCM(encryptedData, Encoding.UTF8.GetBytes(key192Str));

        string actual = Encoding.UTF8.GetString(decryptedData);
        Assert.Equal(expected, actual);
    }

    [Fact]
    public void TestEncryptBytesDataWithAES256GCMShouldEqualToDecryptedData()
    {
        string expected = "wuriyanto";

        byte[] encryptedData = Lib.Aesx.EncryptWithAES256GCM(Encoding.UTF8.GetBytes(expected), Encoding.UTF8.GetBytes(key256Str));
        byte[] decryptedData = Lib.Aesx.DecryptWithAES256GCM(encryptedData, Encoding.UTF8.GetBytes(key256Str));

        string actual = Encoding.UTF8.GetString(decryptedData);
        Assert.Equal(expected, actual);
    }

    [Fact]
    public void TestDecryptEmptyBytesDataWithAES256GCMShouldEqualToDecryptedData()
    {
        string expected = "";

        byte[] decryptedData = Lib.Aesx.DecryptWithAES256GCM(Encoding.UTF8.GetBytes("17C6A0716D8BFA7479330426FD48CE332B6940288607DE3F9186E55F"), Encoding.UTF8.GetBytes(key256Str));

        string actual = Encoding.UTF8.GetString(decryptedData);
        Assert.Equal(expected, actual);
    }

    // AES GCM Encrypt and Decrypt IO Stream
    [Fact]
    public void TestEncryptStreamDataWithAES128GCMShouldEqualToDecryptedData()
    {
        using (FileStream streamInput = File.Open("../../../testdata/burger.png", FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            using (MemoryStream streamEncryptedOutput = new MemoryStream())
            {
                Lib.Aesx.EncryptWithAES128GCM(streamInput, streamEncryptedOutput, Encoding.UTF8.GetBytes(key128Str));

                using (MemoryStream streamDecryptedOutput = new MemoryStream())
                {
                    Lib.Aesx.DecryptWithAES128GCM(streamEncryptedOutput, streamDecryptedOutput, Encoding.UTF8.GetBytes(key128Str));

                    // check if two HASH values of the original input Stream and the resultant Stream of decryption are equal
                    string expected = Lib.Digestx.SHA1Hex(streamInput);
                    string actual = Lib.Digestx.SHA1Hex(streamDecryptedOutput);

                    Assert.Equal(expected, actual);
                }
            }
        }
    }

    [Fact]
    public void TestEncryptStreamDataWithAES192GCMShouldEqualToDecryptedData()
    {
        using (FileStream streamInput = File.Open("../../../testdata/burger.png", FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            using (MemoryStream streamEncryptedOutput = new MemoryStream())
            {
                Lib.Aesx.EncryptWithAES192GCM(streamInput, streamEncryptedOutput, Encoding.UTF8.GetBytes(key192Str));

                using (MemoryStream streamDecryptedOutput = new MemoryStream())
                {
                    Lib.Aesx.DecryptWithAES192GCM(streamEncryptedOutput, streamDecryptedOutput, Encoding.UTF8.GetBytes(key192Str));

                    // check if two HASH values of the original input Stream and the resultant Stream of decryption are equal
                    string expected = Lib.Digestx.SHA1Hex(streamInput);
                    string actual = Lib.Digestx.SHA1Hex(streamDecryptedOutput);

                    Assert.Equal(expected, actual);
                }
            }
        }
    }

    [Fact]
    public void TestEncryptStreamDataWithAES256GCMShouldEqualToDecryptedData()
    {
        using (FileStream streamInput = File.Open("../../../testdata/burger.png", FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            using (MemoryStream streamEncryptedOutput = new MemoryStream())
            {
                Lib.Aesx.EncryptWithAES256GCM(streamInput, streamEncryptedOutput, Encoding.UTF8.GetBytes(key256Str));

                using (MemoryStream streamDecryptedOutput = new MemoryStream())
                {
                    Lib.Aesx.DecryptWithAES256GCM(streamEncryptedOutput, streamDecryptedOutput, Encoding.UTF8.GetBytes(key256Str));

                    // check if two HASH values of the original input Stream and the resultant Stream of decryption are equal
                    string expected = Lib.Digestx.SHA1Hex(streamInput);
                    string actual = Lib.Digestx.SHA1Hex(streamDecryptedOutput);

                    Assert.Equal(expected, actual);
                }
            }
        }
    }
}