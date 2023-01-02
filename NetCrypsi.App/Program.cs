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

            using (MemoryStream streamInput = new MemoryStream(Encoding.UTF8.GetBytes("The hybrid cryptosystem is itself a public-key system, whose public and private keys are the same as in the key encapsulation scheme")))
            {
                using (MemoryStream streamOutput = new MemoryStream())
                {
                    Lib.Aesx.Aesx.EncryptWithAES256GCM(streamInput, streamOutput, Encoding.UTF8.GetBytes(key256Str));
                    Console.WriteLine(Encoding.UTF8.GetString(streamOutput.ToArray()));

                    using (MemoryStream streamOutputDecrypted = new MemoryStream())
                    {
                        streamOutput.Position = 0;
                        Lib.Aesx.Aesx.DecryptWithAES256GCM(streamOutput, streamOutputDecrypted, Encoding.UTF8.GetBytes(key256Str));
                        Console.WriteLine(Encoding.UTF8.GetString(streamOutputDecrypted.ToArray()));
                    }
                }
            }
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
//         public static void Main(string[] args)
//         {

//             string data = "wuriyanto musobar";
//             string key128Str = "kJjG$qMCzbzqW6WW";
//             string key192Str = "kJjG$qMCzbzqW6WWge2ZHFD7";
//             string key256Str = "kJjG$qMCzbzqW6WWge2ZHFD777gjERHO";


//             byte[] encryptedData = Encrypt(Encoding.UTF8.GetBytes(data), Encoding.UTF8.GetBytes(key128Str));
//             Console.WriteLine(Encoding.UTF8.GetString(encryptedData));
//         }

//         static byte[] Encrypt(byte[] plaindata, byte[] key) {
//             byte[] encrypted;
//             var iv = RandomNumberGenerator.GetBytes(16);
//             using (Aes aes = Aes.Create()) {
//                 aes.KeySize = 128;
//                 aes.BlockSize = 128;
//                 aes.Key = key;
//                 aes.IV = aes.IV;

//                 var ivHexStr = Convert.ToHexString(aes.IV);
//                 Console.WriteLine(ivHexStr);
//                 Console.WriteLine(ivHexStr);
//                 Console.WriteLine(Convert.ToHexString(iv));

//                 ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

//                 using (MemoryStream memoryStream = new MemoryStream())
//                 {
//                     using (CryptoStream cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
//                     {
//                         using (StreamWriter streamWriter = new StreamWriter(cryptoStream)) 
//                         {
//                             streamWriter.BaseStream.Write(plaindata);
//                         }

//                         encrypted = Combine(Encoding.UTF8.GetBytes(ivHexStr), Encoding.UTF8.GetBytes(Convert.ToHexString(memoryStream.ToArray())));
//                     }
//                 }
//             }

//             return encrypted;
//         }

//         static byte[] Combine(byte[] first, byte[] second)
//         {
//             byte[] combined = new byte[first.Length+second.Length];
//             Buffer.BlockCopy(first, 0, combined, 0, first.Length);
//             Buffer.BlockCopy(second, 0, combined, first.Length, second.Length);
//             return combined;
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
//             	// KeySize1Kb 1024
//                 const int KeySize1Kb = 1 << 10; // 1024

//                 // KeySize2Kb 2048
//                 const int KeySize2Kb = 1 << 11; // 2048

//                 // KeySize4Kb 4096
//                 const int KeySize4Kb = 1 << 12; // 4096

//             Console.WriteLine("--------------------");

//             using (RSA rsa = RSA.Create(KeySize2Kb))
//             {
//                 Console.WriteLine(rsa.KeySize);
//                 byte[] privateKeyPkcs8Bytes = rsa.ExportPkcs8PrivateKey();
//                 byte[] privateKeyPkcs1Bytes = rsa.ExportRSAPrivateKey();
//                 byte[] publicKeyBytes = rsa.ExportRSAPublicKey();

//                 string privateKeyPkcs8Str = Convert.ToBase64String(privateKeyPkcs8Bytes);
//                 string privateKeyPkcs1Str = Convert.ToBase64String(privateKeyPkcs1Bytes);
//                 string publicKeyStr = Convert.ToBase64String(publicKeyBytes);

//                 // https://blog.ndpar.com/2017/04/17/p1-p8/
//                 // convert rsa public key from PKCS1 format to x509
//                 // openssl rsa -RSAPublicKey_in -in public.key -pubout

//                 // convert rsa private key from PKCS1 format to PKCS8
//                 // openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in private_pkcs1.key -out private_key_pkcs82.key
//                 using (FileStream privateKeyStream = File.Create("private_pkcs8.key"))
//                 {
//                     privateKeyStream.Write(Encoding.UTF8.GetBytes("-----BEGIN PRIVATE KEY-----\n"));
//                     // Output as Base64 with lines chopped at 64 characters
//                     for (var i = 0; i < privateKeyPkcs8Str.Length; i += 64)
//                     {
//                         privateKeyStream.Write(Encoding.UTF8.GetBytes(privateKeyPkcs8Str), i, Math.Min(64, privateKeyPkcs8Str.Length - i));
//                         privateKeyStream.Write(Encoding.UTF8.GetBytes("\n"));
//                     }
//                     privateKeyStream.Write(Encoding.UTF8.GetBytes("-----END PRIVATE KEY-----"));

//                 }

//                 using (FileStream privateKeyStream = File.Create("private_pkcs1.key"))
//                 {
//                     privateKeyStream.Write(Encoding.UTF8.GetBytes("-----BEGIN RSA PRIVATE KEY-----\n"));
//                     // Output as Base64 with lines chopped at 64 characters
//                     for (var i = 0; i < privateKeyPkcs1Str.Length; i += 64)
//                     {
//                         privateKeyStream.Write(Encoding.UTF8.GetBytes(privateKeyPkcs1Str), i, Math.Min(64, privateKeyPkcs1Str.Length - i));
//                         privateKeyStream.Write(Encoding.UTF8.GetBytes("\n"));
//                     }
//                     privateKeyStream.Write(Encoding.UTF8.GetBytes("-----END RSA PRIVATE KEY-----"));

//                 }

//                 using (FileStream publicKeyStream = File.Create("public.key"))
//                 {
//                     publicKeyStream.Write(Encoding.UTF8.GetBytes("-----BEGIN RSA PUBLIC KEY-----\n"));
//                     // Output as Base64 with lines chopped at 64 characters
//                     for (var i = 0; i < publicKeyStr.Length; i += 64)
//                     {
//                         publicKeyStream.Write(Encoding.UTF8.GetBytes(publicKeyStr), i, Math.Min(64, publicKeyStr.Length - i));
//                         publicKeyStream.Write(Encoding.UTF8.GetBytes("\n"));
//                     }
//                     publicKeyStream.Write(Encoding.UTF8.GetBytes("-----END RSA PUBLIC KEY-----"));
//                 }

//                 // Console.WriteLine();
//                 // byte[] privateKeyBytesBase64;
//                 // using (FileStream privateKeyStream = File.Open("private.key", FileMode.Open))
//                 // {

//                 //     using (MemoryStream privateKeyMemStream = new MemoryStream())
//                 //     {
//                 //         privateKeyStream.CopyTo(privateKeyMemStream);
//                 //         privateKeyBytesBase64 = privateKeyMemStream.ToArray();
//                 //     }

//                 //     int bytesRead;
//                 //     byte[] privateKeyBytesDecoded = Convert.FromBase64String(Encoding.UTF8.GetString(privateKeyBytesBase64));
//                 //     rsa.ImportPkcs8PrivateKey(privateKeyBytesDecoded, out bytesRead);

//                 //     Console.WriteLine(bytesRead);

//                 //     // Console.WriteLine(Encoding.UTF8.GetString(privateKeyBytesImport));
//                 // }

//                 // Console.WriteLine();
//                 // using (FileStream privateKeyStream = File.Open("private.key", FileMode.Open))
//                 // {
//                 //     using (MemoryStream memoryStream = new MemoryStream())
//                 //     {
//                 //         using (StreamReader streamReader = new StreamReader(privateKeyStream))
//                 //         {
//                 //             string? line;
//                 //             Console.WriteLine(privateKeyStream.Length);

//                 //             while((line = streamReader.ReadLine()) != null)
//                 //             {
//                 //                 if (line.Contains("BEGIN") || line.Contains("END"))
//                 //                 {
//                 //                     continue;
//                 //                 }

//                 //                 // line = line.Replace("\n", "").Replace("\r", "");

//                 //                 memoryStream.Write(Convert.FromBase64String(line));
//                 //             }
//                 //         }

//                 //         // Console.WriteLine(Encoding.UTF8.GetString(memoryStream.ToArray()));

//                 //         int bytesRead;
//                 //         rsa.ImportPkcs8PrivateKey(memoryStream.ToArray(), out bytesRead);

//                 //         Console.WriteLine(bytesRead);
//                 //     }
//                 // }

//                 // Console.WriteLine();
//                 // using (FileStream publicKeyStream = File.Open("public.key", FileMode.Open))
//                 // {
//                 //     using (MemoryStream memoryStream = new MemoryStream())
//                 //     {
//                 //         using (StreamReader streamReader = new StreamReader(publicKeyStream))
//                 //         {
//                 //             string? line;

//                 //             while((line = streamReader.ReadLine()) != null)
//                 //             {
//                 //                 if (line.Contains("BEGIN") || line.Contains("END"))
//                 //                 {
//                 //                     continue;
//                 //                 }

//                 //                 // line = line.Replace("\n", "").Replace("\r", "");

//                 //                 memoryStream.Write(Convert.FromBase64String(line));
//                 //             }
//                 //         }

//                 //         // Console.WriteLine(Encoding.UTF8.GetString(memoryStream.ToArray()));

//                 //         int bytesRead;
//                 //         rsa.ImportRSAPublicKey(memoryStream.ToArray(), out bytesRead);

//                 //         Console.WriteLine(bytesRead);
//                 //     }
//                 // }

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