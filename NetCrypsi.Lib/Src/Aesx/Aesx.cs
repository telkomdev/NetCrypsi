using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace NetCrypsi.Lib.Aesx
{
    public sealed class Aesx
    {
        // BlockSize in bits, or 16 in bytes
        private const int BlockSize = 128;

        private Aesx()
        {

        }

        // CBC
        public static byte[] EncryptWithAES128CBC(byte[] plaindata, byte[] key) => Lib.Aesx.AesCbc.EncryptWithAES128CBC(plaindata, key);

        public static byte[] EncryptWithAES192CBC(byte[] plaindata, byte[] key) => Lib.Aesx.AesCbc.EncryptWithAES192CBC(plaindata, key);

        public static byte[] EncryptWithAES256CBC(byte[] plaindata, byte[] key) => Lib.Aesx.AesCbc.EncryptWithAES256CBC(plaindata, key);

        public static byte[] DecryptWithAES128CBC(byte[] encryptedData, byte[] key) => Lib.Aesx.AesCbc.DecryptWithAES128CBC(encryptedData, key);

        public static byte[] DecryptWithAES192CBC(byte[] encryptedData, byte[] key) => Lib.Aesx.AesCbc.DecryptWithAES192CBC(encryptedData, key);

        public static byte[] DecryptWithAES256CBC(byte[] encryptedData, byte[] key) => Lib.Aesx.AesCbc.DecryptWithAES256CBC(encryptedData, key);

        // io
        public static void EncryptWithAES128CBC(Stream plaindata, Stream outEncryptedData, byte[] key) => Lib.Aesx.AesCbc.EncryptWithAES128CBC(plaindata, outEncryptedData, key);

        public static void EncryptWithAES192CBC(Stream plaindata, Stream outEncryptedData, byte[] key) => Lib.Aesx.AesCbc.EncryptWithAES192CBC(plaindata, outEncryptedData, key);

        public static void EncryptWithAES256CBC(Stream plaindata, Stream outEncryptedData, byte[] key) => Lib.Aesx.AesCbc.EncryptWithAES256CBC(plaindata, outEncryptedData, key);

        public static void DecryptWithAES128CBC(Stream encryptedData, Stream outPlainData, byte[] key) => Lib.Aesx.AesCbc.DecryptWithAES128CBC(encryptedData, outPlainData, key);

        public static void DecryptWithAES192CBC(Stream encryptedData, Stream outPlainData, byte[] key) => Lib.Aesx.AesCbc.DecryptWithAES192CBC(encryptedData, outPlainData, key);

        public static void DecryptWithAES256CBC(Stream encryptedData, Stream outPlainData, byte[] key) => Lib.Aesx.AesCbc.DecryptWithAES256CBC(encryptedData, outPlainData, key);

        // GCM
        public static byte[] EncryptWithAES128GCM(byte[] plaindata, byte[] key) => Lib.Aesx.AesGcm.EncryptWithAES128GCM(plaindata, key);

        public static byte[] EncryptWithAES192GCM(byte[] plaindata, byte[] key) => Lib.Aesx.AesGcm.EncryptWithAES192GCM(plaindata, key);

        public static byte[] EncryptWithAES256GCM(byte[] plaindata, byte[] key) => Lib.Aesx.AesGcm.EncryptWithAES256GCM(plaindata, key);

        public static byte[] DecryptWithAES128GCM(byte[] encryptedData, byte[] key) => Lib.Aesx.AesGcm.DecryptWithAES128GCM(encryptedData, key);

        public static byte[] DecryptWithAES192GCM(byte[] encryptedData, byte[] key) => Lib.Aesx.AesGcm.DecryptWithAES192GCM(encryptedData, key);

        public static byte[] DecryptWithAES256GCM(byte[] encryptedData, byte[] key) => Lib.Aesx.AesGcm.DecryptWithAES256GCM(encryptedData, key);

        // io
        public static void EncryptWithAES128GCM(Stream plaindata, Stream outEncryptedData, byte[] key) => Lib.Aesx.AesGcm.EncryptWithAES128GCM(plaindata, outEncryptedData, key);

        public static void EncryptWithAES192GCM(Stream plaindata, Stream outEncryptedData, byte[] key) => Lib.Aesx.AesGcm.EncryptWithAES192GCM(plaindata, outEncryptedData, key);

        public static void EncryptWithAES256GCM(Stream plaindata, Stream outEncryptedData, byte[] key) => Lib.Aesx.AesGcm.EncryptWithAES256GCM(plaindata, outEncryptedData, key);

        public static void DecryptWithAES128GCM(Stream encryptedData, Stream outPlainData, byte[] key) => Lib.Aesx.AesGcm.DecryptWithAES128GCM(encryptedData, outPlainData, key);

        public static void DecryptWithAES192GCM(Stream encryptedData, Stream outPlainData, byte[] key) => Lib.Aesx.AesGcm.DecryptWithAES192GCM(encryptedData, outPlainData, key);

        public static void DecryptWithAES256GCM(Stream encryptedData, Stream outPlainData, byte[] key) => Lib.Aesx.AesGcm.DecryptWithAES256GCM(encryptedData, outPlainData, key);
    }
}
