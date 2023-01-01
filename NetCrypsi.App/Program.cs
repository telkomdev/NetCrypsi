using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace NetCrypsi.App
{
    public class Application
    {
        // https://learn.microsoft.com/en-us/dotnet/standard/security/cryptography-model
        // https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.aes?view=net-7.0
        public static void Main(string[] args)
        {

            string data = "The nonce associated with this message, which must match the value provided during encryption";
            string key128Str = "kJjG$qMCzbzqW6WW";
            string key192Str = "kJjG$qMCzbzqW6WWge2ZHFD7";
            string key256Str = "kJjG$qMCzbzqW6WWge2ZHFD777gjERHO";


            byte[] encryptedData = Lib.Aesx.AesGcm.EncryptWithAES192GCM(Encoding.UTF8.GetBytes(data), Encoding.UTF8.GetBytes(key192Str));
            Console.WriteLine(Encoding.UTF8.GetString(encryptedData));
            
            byte[] decryptedData = Lib.Aesx.AesGcm.DecryptWithAES256GCM(Encoding.UTF8.GetBytes("cafe01407195f04c255fe02fcf69579ce382874c099b94adc2950ce60ddc6c2bbca9cc7099"), Encoding.UTF8.GetBytes(key256Str));
            Console.WriteLine(Encoding.UTF8.GetString(decryptedData));
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
//         // https://learn.microsoft.com/en-us/dotnet/standard/security/cryptography-model
//         // https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.aes?view=net-7.0
//         public static void Main(string[] args)
//         {

//             string data = "wuriyanto musobar";
//             string key128Str = "kJjG$qMCzbzqW6WW";
//             string key192Str = "kJjG$qMCzbzqW6WWge2ZHFD7";
//             string key256Str = "kJjG$qMCzbzqW6WWge2ZHFD777gjERHO";


//             byte[] encryptedData = Lib.Aesx.AesCbc.EncryptWithAES192CBC(Encoding.UTF8.GetBytes(data), Encoding.UTF8.GetBytes(key192Str));
//             Console.WriteLine(Encoding.UTF8.GetString(encryptedData));
            
//             byte[] decryptedData = Lib.Aesx.AesCbc.DecryptWithAES128CBC(Encoding.UTF8.GetBytes("B1944106AF644E07B9B934231306F32A832C2C7964DADC513F737611BA6FA55EEA6F92449011D71ABE877072C6C1C506"), Encoding.UTF8.GetBytes(key128Str));
//             Console.WriteLine(Encoding.UTF8.GetString(decryptedData));

//             Console.WriteLine("--------------------");
//             using (MemoryStream srcStream = new MemoryStream(Encoding.UTF8.GetBytes("wuriyanto hehehe")))
//             {
//                 using (MemoryStream encryptedOutStream = new MemoryStream())
//                 {
//                     Lib.Aesx.AesCbc.EncryptWithAES128CBCIO(srcStream, encryptedOutStream, Encoding.UTF8.GetBytes(key128Str));
//                     byte[] encryptedData2 = encryptedOutStream.ToArray();
//                     Console.WriteLine(Encoding.UTF8.GetString(encryptedData2));
                    
//                     using (MemoryStream decryptedOutStream = new MemoryStream())
//                     {
//                         Lib.Aesx.AesCbc.DecryptWithAES128CBCIO(encryptedOutStream, decryptedOutStream, Encoding.UTF8.GetBytes(key128Str));
//                         Console.WriteLine(Encoding.UTF8.GetString(decryptedOutStream.ToArray()));
//                     }
                
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