using System;
using System.Text;

namespace NetCrypsi.Tests;

public class DigestTest
{
    // MD5
    [Fact]
    public void TestMD5HexShouldEqualToExpected()
    {
        string expected = "60e1bc04fa194a343b50ce67f4afcff8";

        string actual = Lib.Digestx.Digestx.MD5Hex(Encoding.UTF8.GetBytes("wuriyanto"));
        Assert.Equal(expected.ToLower(), actual.ToLower());
    }

    [Fact]
    public void TestMD5HexLongTextShouldEqualToExpected()
    {
        string expected = "2deae4977e23469cb359ff61a74b320d";

        string actual = Lib.Digestx.Digestx.MD5Hex(Encoding.UTF8.GetBytes("In cryptography, a hybrid cryptosystem is one which combines the convenience of a public-key cryptosystem with the efficiency of a symmetric-key cryptosystem.[1] Public-key cryptosystems are convenient in that they do not require"));
        Assert.Equal(expected.ToLower(), actual.ToLower());
    }

    [Fact]
    public void TestMD5HexShouldNotEqualToExpected()
    {
        string expected = "60e1bc04fa194a343b50ce67f4afcfff";

        string actual = Lib.Digestx.Digestx.MD5Hex(Encoding.UTF8.GetBytes("wuriyanto"));
        Assert.NotEqual(expected.ToLower(), actual.ToLower());
    }

    // SHA1
    [Fact]
    public void TestSHA1HexShouldEqualToExpected()
    {
        string expected = "afd2bd72af0c346a2ab14d50746835d3ccd1dd5f";

        string actual = Lib.Digestx.Digestx.SHA1Hex(Encoding.UTF8.GetBytes("wuriyanto"));
        Assert.Equal(expected.ToLower(), actual.ToLower());
    }

    [Fact]
    public void TestSHA1HexLongTextShouldEqualToExpected()
    {
        string expected = "d3f2ae5857e2a1a29a835b1b8146555f3c2f0af6";

        string actual = Lib.Digestx.Digestx.SHA1Hex(Encoding.UTF8.GetBytes("In cryptography, a hybrid cryptosystem is one which combines the convenience of a public-key cryptosystem with the efficiency of a symmetric-key cryptosystem.[1] Public-key cryptosystems are convenient in that they do not require"));
        Assert.Equal(expected.ToLower(), actual.ToLower());
    }

    [Fact]
    public void TestSHA1HexShouldNotEqualToExpected()
    {
        string expected = "afd2bd72af0c346a2ab14d50746835d3ccd1dd55";

        string actual = Lib.Digestx.Digestx.SHA1Hex(Encoding.UTF8.GetBytes("wuriyanto"));
        Assert.NotEqual(expected.ToLower(), actual.ToLower());
    }

    // SHA256
    [Fact]
    public void TestSHA256HexShouldEqualToExpected()
    {
        string expected = "7da544fa170151239b9886c0c905736fe3e8b07e68aefaba0633272aee47af87";

        string actual = Lib.Digestx.Digestx.SHA256Hex(Encoding.UTF8.GetBytes("wuriyanto"));
        Assert.Equal(expected.ToLower(), actual.ToLower());
    }

    [Fact]
    public void TestSHA256HexLongTextShouldEqualToExpected()
    {
        string expected = "0dedb636c97ff73bb932996abbad9bdef161b68c6696784f88c1fcf0794338d3";

        string actual = Lib.Digestx.Digestx.SHA256Hex(Encoding.UTF8.GetBytes("In cryptography, a hybrid cryptosystem is one which combines the convenience of a public-key cryptosystem with the efficiency of a symmetric-key cryptosystem.[1] Public-key cryptosystems are convenient in that they do not require"));
        Assert.Equal(expected.ToLower(), actual.ToLower());
    }

    [Fact]
    public void TestSHA256HexShouldNotEqualToExpected()
    {
        string expected = "7da544fa170151239b9886c0c905736fe3e8b07e68aefaba0633272aee47af88";

        string actual = Lib.Digestx.Digestx.SHA256Hex(Encoding.UTF8.GetBytes("wuriyanto"));
        Assert.NotEqual(expected.ToLower(), actual.ToLower());
    }

    // SHA384
    [Fact]
    public void TestSHA384HexShouldEqualToExpected()
    {
        string expected = "2bf236501ecea775cd0eac6da0632eb236e514f29c2aff06a42819fe3b1f3d5b8aefe8c1608a8f5a4d832090902f84a1";

        string actual = Lib.Digestx.Digestx.SHA384Hex(Encoding.UTF8.GetBytes("wuriyanto"));
        Assert.Equal(expected.ToLower(), actual.ToLower());
    }

    [Fact]
    public void TestSHA384HexLongTextShouldEqualToExpected()
    {
        string expected = "658eb97762ac1fd44d9062cf49014269cf87ea4938bdd0ae3193ce6375942f2942d75a6863aea55f8149cf0b13d311b6";

        string actual = Lib.Digestx.Digestx.SHA384Hex(Encoding.UTF8.GetBytes("In cryptography, a hybrid cryptosystem is one which combines the convenience of a public-key cryptosystem with the efficiency of a symmetric-key cryptosystem.[1] Public-key cryptosystems are convenient in that they do not require"));
        Assert.Equal(expected.ToLower(), actual.ToLower());
    }

    [Fact]
    public void TestSHA384HexShouldNotEqualToExpected()
    {
        string expected = "2bf236501ecea775cd0eac6da0632eb236e514f29c2aff06a42819fe3b1f3d5b8aefe8c1608a8f5a4d832090902f84aa";

        string actual = Lib.Digestx.Digestx.SHA384Hex(Encoding.UTF8.GetBytes("wuriyanto"));
        Assert.NotEqual(expected.ToLower(), actual.ToLower());
    }

    // SHA512
    [Fact]
    public void TestSHA512HexShouldEqualToExpected()
    {
        string expected = "5adf884c57a5dc4f353bb08a138953e98320c35843ec86dd42e866e9111f39f502dd250a31f421c9eae8b0593540c30b4ecba6f7f5356632aeea308ee5a5a206";

        string actual = Lib.Digestx.Digestx.SHA512Hex(Encoding.UTF8.GetBytes("wuriyanto"));
        Assert.Equal(expected.ToLower(), actual.ToLower());
    }

    [Fact]
    public void TestSHA512HexLongTextShouldEqualToExpected()
    {
        string expected = "7dbd3db1159a2ddb2a3be939a88f6042948b90b032eb8a02a65ede6dd50226fa708827364c164fdcb16f29cc7d71231e1fc5089b4a96f6a42a6aea4168986e61";

        string actual = Lib.Digestx.Digestx.SHA512Hex(Encoding.UTF8.GetBytes("In cryptography, a hybrid cryptosystem is one which combines the convenience of a public-key cryptosystem with the efficiency of a symmetric-key cryptosystem.[1] Public-key cryptosystems are convenient in that they do not require"));
        Assert.Equal(expected.ToLower(), actual.ToLower());
    }

    [Fact]
    public void TestSHA512HexShouldNotEqualToExpected()
    {
        string expected = "5adf884c57a5dc4f353bb08a138953e98320c35843ec86dd42e866e9111f39f502dd250a31f421c9eae8b0593540c30b4ecba6f7f5356632aeea308ee5a5a202";

        string actual = Lib.Digestx.Digestx.SHA512Hex(Encoding.UTF8.GetBytes("wuriyanto"));
        Assert.NotEqual(expected.ToLower(), actual.ToLower());
    }
}