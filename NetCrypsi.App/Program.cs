using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace NetCrypsi.App
{
    public class Application
    {
        public static void Main(string[] args)
        {

            string data = "wuriyanto musobar";
            string key128Str = "kJjG$qMCzbzqW6WW";
            string key192Str = "kJjG$qMCzbzqW6WWge2ZHFD7";
            string key256Str = "kJjG$qMCzbzqW6WWge2ZHFD777gjERHO";


            byte[] encryptedData = Lib.Aesx.Aesx.EncryptWithAES256GCM(Encoding.UTF8.GetBytes(data), Encoding.UTF8.GetBytes(key256Str));
            Console.WriteLine(Encoding.UTF8.GetString(encryptedData));

            byte[] decryptedData = Lib.Aesx.Aesx.DecryptWithAES256GCM(Encoding.UTF8.GetBytes("2bf255478288eea26a91b658a97c050d4ec841e8de244aae4f8aaa6e0413234504728e946783c4925460fc06fedb7a627dad42dcb3a9bd4e1bb556c69be79029b8daf08cec7669d16229a1895e9c00ec58b28edf36edab3db5f3359d3df5d7f132a0e628e42f1551329972bd0f752254be273c33ba32348f30"), Encoding.UTF8.GetBytes(key256Str));
            Console.WriteLine(Encoding.UTF8.GetString(decryptedData));

            using (FileStream streamInput = File.Open("./NetCrypsi.Tests/testdata/burger.png", FileMode.Open))
            {
                using (FileStream streamOutput = File.Create("burger.bin"))
                {
                    Lib.Aesx.Aesx.EncryptWithAES256GCM(streamInput, streamOutput, Encoding.UTF8.GetBytes(key256Str));
                }
            }

            using (FileStream streamInput = File.Open("burger.bin", FileMode.Open))
            {
                using (FileStream streamOutput = File.Create("burger_decrypt.png"))
                {
                    Lib.Aesx.Aesx.DecryptWithAES256GCM(streamInput, streamOutput, Encoding.UTF8.GetBytes(key256Str));
                }
            }

            byte[] emptyEncryptedData = Lib.Aesx.Aesx.EncryptWithAES256CBC(Encoding.UTF8.GetBytes(""), Encoding.UTF8.GetBytes(key256Str));
            Console.WriteLine(Encoding.UTF8.GetString(emptyEncryptedData));

            byte[] emptyDecryptedData = Lib.Aesx.Aesx.DecryptWithAES256CBC(Encoding.UTF8.GetBytes("91d67cce84b7a189d178697ef78fc9b4059b61b33004dc33d9be139afadd0660"), Encoding.UTF8.GetBytes(key256Str));
            Console.WriteLine(Encoding.UTF8.GetString(emptyDecryptedData));
        }
    }
}

// using System;
// using System.IO;
// using System.Security.Cryptography;
// using System.Text;

// namespace NetCrypsi.App
// {
//     public class Application
//     {
//         public static void Main(string[] args)
//         {

//             Console.WriteLine("--------------------");
//             Console.WriteLine(Lib.Digestx.Digestx.MD5Hex(Encoding.UTF8.GetBytes("wuriyanto")));
//             Console.WriteLine(Lib.Digestx.Digestx.SHA1Hex(Encoding.UTF8.GetBytes("wuriyanto")));
//             Console.WriteLine(Lib.Digestx.Digestx.SHA256Hex(Encoding.UTF8.GetBytes("wuriyanto")));
//             Console.WriteLine(Lib.Digestx.Digestx.SHA384Hex(Encoding.UTF8.GetBytes("wuriyanto")));
//             Console.WriteLine(Lib.Digestx.Digestx.SHA512Hex(Encoding.UTF8.GetBytes("wuriyanto")));
//             Console.WriteLine(Lib.Digestx.Digestx.SHA512Hex(Encoding.UTF8.GetBytes("wuriyantomusobar")));

//             Console.WriteLine("--------------------");
//             Console.WriteLine(Lib.Hmacx.Hmacx.MD5Hex(Encoding.UTF8.GetBytes("abc$#128djdyAgbjau&YAnmcbagryt5x"), Encoding.UTF8.GetBytes("wuriyanto")));
//             Console.WriteLine(Lib.Hmacx.Hmacx.SHA1Hex(Encoding.UTF8.GetBytes("abc$#128djdyAgbjau&YAnmcbagryt5x"), Encoding.UTF8.GetBytes("wuriyanto")));
//             Console.WriteLine(Lib.Hmacx.Hmacx.SHA256Hex(Encoding.UTF8.GetBytes("abc$#128djdyAgbjau&YAnmcbagryt5x"), Encoding.UTF8.GetBytes("wuriyanto")));
//             Console.WriteLine(Lib.Hmacx.Hmacx.SHA384Hex(Encoding.UTF8.GetBytes("abc$#128djdyAgbjau&YAnmcbagryt5x"), Encoding.UTF8.GetBytes("wuriyanto")));
//             Console.WriteLine(Lib.Hmacx.Hmacx.SHA512Hex(Encoding.UTF8.GetBytes("abc$#128djdyAgbjau&YAnmcbagryt5x"), Encoding.UTF8.GetBytes("wuriyanto")));
//             Console.WriteLine(Lib.Hmacx.Hmacx.SHA512Hex(Encoding.UTF8.GetBytes("abc$#128djdyAgbjau&YAnmcbagryt5x"), Encoding.UTF8.GetBytes("wuriyantomusobar")));

//             Console.WriteLine("--------------------");

//             using (MemoryStream fakeStream = new MemoryStream(Encoding.UTF8.GetBytes("wuriyanto")))
//             {
//                 Console.WriteLine(Lib.Hmacx.Hmacx.SHA512Hex(Encoding.UTF8.GetBytes("abc$#128djdyAgbjau&YAnmcbagryt5x"), fakeStream));
//             }
//         }
//     }
// }

// using System;
// using System.IO;
// using System.Security.Cryptography;
// using System.Text;

// namespace NetCrypsi.App
// {
//     public class Application
//     {
// https://blog.ndpar.com/2017/04/17/p1-p8/
// convert rsa public key from PKCS1 format to x509
// openssl rsa -RSAPublicKey_in -in public.key -pubout

// convert rsa private key from PKCS1 format to PKCS8
// openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in private_pkcs1.key -out private_key_pkcs82.key
//         public static void Main(string[] args)
//         {
//             Lib.Rsax.Rsax rsax = Lib.Rsax.Rsax.Create(Lib.Rsax.Rsax.KeySize2Kb);
//             Console.WriteLine(rsax.ExportPKCS1PublicKeyToHexStr());

//             // using (RSA rsa = RSA.Create())
//             // {
//             //     // using (FileStream privateKeyStream = File.Open("private_key_pkcs82.key", FileMode.Open))
//             //     // {
//             //     //     byte[] privateKey = Lib.Rsax.Rsax.LoadKeyFromPem(privateKeyStream);
//             //     //     rsa.ImportPkcs8PrivateKey(privateKey, out _);
//             //     // }

//             //     rsa.ImportPkcs8PrivateKey(Lib.Rsax.Rsax.LoadKeyFromHexStr(rsax.ExportPKCS8PrivateKeyToHexStr()), out _);
//             //     rsa.ImportRSAPrivateKey(Lib.Rsax.Rsax.LoadKeyFromHexStr(rsax.ExportPKCS1PrivateKeyToHexStr()), out _);
//             //     rsa.ImportRSAPublicKey(Lib.Rsax.Rsax.LoadKeyFromHexStr(rsax.ExportPKCS1PublicKeyToHexStr()), out _);

//             //     Console.WriteLine(rsa.KeySize);
//             // }

//             using (FileStream privateKeyStream = File.Create("private_pkcs8.key"))
//             {
//                 rsax.ExportPKCS8PrivateKeyToStreamPem(privateKeyStream);

//             }

//             using (FileStream privateKeyStream = File.Create("private_pkcs1.key"))
//             {
//                 rsax.ExportPKCS1PrivateKeyToStreamPem(privateKeyStream);
//             }

//             using (FileStream publicKeyStream = File.Create("public.key"))
//             {
//                 rsax.ExportPKCS1PublicKeyToStreamPem(publicKeyStream);
//             }
//         }
//     }
// }

// using System;
// using System.IO;
// using System.Security.Cryptography;
// using System.Text;

// namespace NetCrypsi.App
// {
//     public class Application
//     {
//         public static void Main(string[] args)
//         {
//             Lib.Rsax.Rsax rsax = Lib.Rsax.Rsax.Create(Lib.Rsax.Rsax.KeySize2Kb);

//             byte[] publicKeyBytes;
//             byte[] privateKeyBytes;

//             using (FileStream publicKeyStream = File.Open("public.key", FileMode.Open))
//             {
//                 publicKeyBytes = Lib.Rsax.Rsax.LoadKeyFromPem(publicKeyStream);
//             }

//             using (FileStream privateKeyStream = File.Open("private_pkcs8.key", FileMode.Open))
//             {
//                 privateKeyBytes = Lib.Rsax.Rsax.LoadKeyFromPem(privateKeyStream);
//             }

//             string data = "Below is an online tool to perform RSA encryption and decryption as a RSA calculator";

//             byte[] encryptedData = Lib.Rsax.Encryption.EncryptWithOaepSHA512(publicKeyBytes, Encoding.UTF8.GetBytes(data));

//             Console.WriteLine(Convert.ToBase64String(encryptedData));

//             byte[] decryptedData = Lib.Rsax.Encryption.DecryptWithOaepSHA512(privateKeyBytes, Convert.FromBase64String(Convert.ToBase64String(encryptedData)));
//             Console.WriteLine(Encoding.UTF8.GetString(decryptedData));
//         }
//     }
// }

// using System;
// using System.IO;
// using System.Security.Cryptography;
// using System.Text;

// namespace NetCrypsi.App
// {
//     public class Application
//     {
//         public static void Main(string[] args)
//         {
//             Lib.Rsax.Rsax rsax = Lib.Rsax.Rsax.Create(Lib.Rsax.Rsax.KeySize2Kb);

//             byte[] publicKeyBytes;
//             byte[] privateKeyBytes;

//             using (FileStream publicKeyStream = File.Open("public.key", FileMode.Open))
//             {
//                 publicKeyBytes = Lib.Rsax.Rsax.LoadKeyFromPem(publicKeyStream);
//             }

//             using (FileStream privateKeyStream = File.Open("private_pkcs8.key", FileMode.Open))
//             {
//                 privateKeyBytes = Lib.Rsax.Rsax.LoadKeyFromPem(privateKeyStream);
//             }

//             using (FileStream plainDataStream = File.Open("burger.png", FileMode.Open))
//             {
//                 using (FileStream encryptedDataStream = File.Create("burger_encrypted.bin"))
//                 {
//                     Lib.Rsax.Encryption.EncryptWithOaepMD5(publicKeyBytes, plainDataStream, encryptedDataStream);
//                 }
//             }
//         }
//     }
// }

// using System;
// using System.IO;
// using System.Security.Cryptography;
// using System.Text;

// namespace NetCrypsi.App
// {
//     public class Application
//     {
//         public static void Main(string[] args)
//         {
//             Lib.Rsax.Rsax rsax = Lib.Rsax.Rsax.Create(Lib.Rsax.Rsax.KeySize2Kb);

//             byte[] publicKeyBytes;
//             byte[] privateKeyBytes;

//             using (FileStream publicKeyStream = File.Open("public.key", FileMode.Open))
//             {
//                 publicKeyBytes = Lib.Rsax.Rsax.LoadKeyFromPem(publicKeyStream);
//             }

//             using (FileStream privateKeyStream = File.Open("private_pkcs8.key", FileMode.Open))
//             {
//                 privateKeyBytes = Lib.Rsax.Rsax.LoadKeyFromPem(privateKeyStream);
//             }

//             string data = "Below is an online tool to perform RSA encryption and decryption as a RSA calculator";

//             byte[] signature = Lib.Rsax.DigitalSignature.SignWithPssSHA512(privateKeyBytes, Encoding.UTF8.GetBytes(data));

//             Console.WriteLine(Convert.ToHexString(signature));

//             bool signatureValid = Lib.Rsax.DigitalSignature.VerifySignatureWithPssSHA512(publicKeyBytes, Convert.FromHexString(Convert.ToHexString(signature)), Encoding.UTF8.GetBytes(data));
//             Console.WriteLine(signatureValid);
//         }
//     }
// }