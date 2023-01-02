using System;
using System.Text;

namespace NetCrypsi.Tests;

public class HmacTest
{
    // MD5
    [Fact]
    public void TestMD5HexShouldEqualToExpected()
    {
        string expected = "d213b2e973c1a5d704255518af6d073c";

        string actual = Lib.Hmacx.Hmacx.MD5Hex(Encoding.UTF8.GetBytes("abc$#128djdyAgbjau&YAnmcbagryt5x"), Encoding.UTF8.GetBytes("wuriyanto"));
        Assert.Equal(expected.ToLower(), actual.ToLower());
    }

    [Fact]
    public void TestMD5HexShouldNotEqualToExpectedWhenKeyIsInvalid()
    {
        string expected = "d213b2e973c1a5d704255518af6d073c";

        string actual = Lib.Hmacx.Hmacx.MD5Hex(Encoding.UTF8.GetBytes("abc$#128djdyAgbjau&YAnmcbagryt5v"), Encoding.UTF8.GetBytes("wuriyanto"));
        Assert.NotEqual(expected.ToLower(), actual.ToLower());
    }

    [Fact]
    public void TestMD5HexShouldThrowExceptionWhenKeyLessThanExpected()
    {
        Assert.Throws<ArgumentException>(() => Lib.Hmacx.Hmacx.MD5Hex(Encoding.UTF8.GetBytes("abc$#128djdyAgbjau&YAnmcbagryt"), Encoding.UTF8.GetBytes("wuriyanto")));
    }

    // SHA1
    [Fact]
    public void TestSHA1HexShouldEqualToExpected()
    {
        string expected = "69fa82ae1f1398e6e570a4780df908adad3998df";

        string actual = Lib.Hmacx.Hmacx.SHA1Hex(Encoding.UTF8.GetBytes("abc$#128djdyAgbjau&YAnmcbagryt5x"), Encoding.UTF8.GetBytes("wuriyanto"));
        Assert.Equal(expected.ToLower(), actual.ToLower());
    }

    [Fact]
    public void TestSHA1HexShouldNotEqualToExpectedWhenKeyIsInvalid()
    {
        string expected = "69fa82ae1f1398e6e570a4780df908adad3998df";

        string actual = Lib.Hmacx.Hmacx.SHA1Hex(Encoding.UTF8.GetBytes("abc$#128djdyAgbjau&YAnmcbagryt5v"), Encoding.UTF8.GetBytes("wuriyanto"));
        Assert.NotEqual(expected.ToLower(), actual.ToLower());
    }

    [Fact]
    public void TestSHA1HexShouldThrowExceptionWhenKeyLessThanExpected()
    {
        Assert.Throws<ArgumentException>(() => Lib.Hmacx.Hmacx.SHA1Hex(Encoding.UTF8.GetBytes("abc$#128djdyAgbjau&YAnmcbagryt"), Encoding.UTF8.GetBytes("wuriyanto")));
    }

    // SHA256
    [Fact]
    public void TestSHA256HexShouldEqualToExpected()
    {
        string expected = "9f46bcc1bdc24ff2d4b6f811c1dd7e053089e515b0525c2b2a7ff25c28eb4240";

        string actual = Lib.Hmacx.Hmacx.SHA256Hex(Encoding.UTF8.GetBytes("abc$#128djdyAgbjau&YAnmcbagryt5x"), Encoding.UTF8.GetBytes("wuriyanto"));
        Assert.Equal(expected.ToLower(), actual.ToLower());
    }

    [Fact]
    public void TestSHA256HexShouldNotEqualToExpectedWhenKeyIsInvalid()
    {
        string expected = "9f46bcc1bdc24ff2d4b6f811c1dd7e053089e515b0525c2b2a7ff25c28eb4240";

        string actual = Lib.Hmacx.Hmacx.SHA256Hex(Encoding.UTF8.GetBytes("abc$#128djdyAgbjau&YAnmcbagryt5v"), Encoding.UTF8.GetBytes("wuriyanto"));
        Assert.NotEqual(expected.ToLower(), actual.ToLower());
    }

    [Fact]
    public void TestSHA256HexShouldThrowExceptionWhenKeyLessThanExpected()
    {
        Assert.Throws<ArgumentException>(() => Lib.Hmacx.Hmacx.SHA256Hex(Encoding.UTF8.GetBytes("abc$#128djdyAgbjau&YAnmcbagryt"), Encoding.UTF8.GetBytes("wuriyanto")));
    }

    // SHA384
    [Fact]
    public void TestSHA384HexShouldEqualToExpected()
    {
        string expected = "69b5b98267f760b5dc39cde790adc89358c9a59d7eac7e76c5a9e7acb9c037d0293810251de16afdf96adcbf9e512ed4";

        string actual = Lib.Hmacx.Hmacx.SHA384Hex(Encoding.UTF8.GetBytes("abc$#128djdyAgbjau&YAnmcbagryt5x"), Encoding.UTF8.GetBytes("wuriyanto"));
        Assert.Equal(expected.ToLower(), actual.ToLower());
    }

    [Fact]
    public void TestSHA384HexShouldNotEqualToExpectedWhenKeyIsInvalid()
    {
        string expected = "69b5b98267f760b5dc39cde790adc89358c9a59d7eac7e76c5a9e7acb9c037d0293810251de16afdf96adcbf9e512ed4";

        string actual = Lib.Hmacx.Hmacx.SHA384Hex(Encoding.UTF8.GetBytes("abc$#128djdyAgbjau&YAnmcbagryt5v"), Encoding.UTF8.GetBytes("wuriyanto"));
        Assert.NotEqual(expected.ToLower(), actual.ToLower());
    }

    [Fact]
    public void TestSHA384HexShouldThrowExceptionWhenKeyLessThanExpected()
    {
        Assert.Throws<ArgumentException>(() => Lib.Hmacx.Hmacx.SHA384Hex(Encoding.UTF8.GetBytes("abc$#128djdyAgbjau&YAnmcbagryt"), Encoding.UTF8.GetBytes("wuriyanto")));
    }

    // SHA512
    [Fact]
    public void TestSHA512HexShouldEqualToExpected()
    {
        string expected = "0084af8c8d831581b30f3ef2a250355bb04f2b2ca632d656ab8dce2b34692e5238ed19f7638070a115196dd928dfff3717dddf9d072ae9c26716c8faa11a25f8";

        string actual = Lib.Hmacx.Hmacx.SHA512Hex(Encoding.UTF8.GetBytes("abc$#128djdyAgbjau&YAnmcbagryt5x"), Encoding.UTF8.GetBytes("wuriyanto"));
        Assert.Equal(expected.ToLower(), actual.ToLower());
    }

    [Fact]
    public void TestSHA512HexShouldNotEqualToExpectedWhenKeyIsInvalid()
    {
        string expected = "0084af8c8d831581b30f3ef2a250355bb04f2b2ca632d656ab8dce2b34692e5238ed19f7638070a115196dd928dfff3717dddf9d072ae9c26716c8faa11a25f8";

        string actual = Lib.Hmacx.Hmacx.SHA512Hex(Encoding.UTF8.GetBytes("abc$#128djdyAgbjau&YAnmcbagryt5v"), Encoding.UTF8.GetBytes("wuriyanto"));
        Assert.NotEqual(expected.ToLower(), actual.ToLower());
    }

    [Fact]
    public void TestSHA512HexShouldThrowExceptionWhenKeyLessThanExpected()
    {
        Assert.Throws<ArgumentException>(() => Lib.Hmacx.Hmacx.SHA512Hex(Encoding.UTF8.GetBytes("abc$#128djdyAgbjau&YAnmcbagryt"), Encoding.UTF8.GetBytes("wuriyanto")));
    }
}