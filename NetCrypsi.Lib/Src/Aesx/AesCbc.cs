using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace NetCrypsi.Lib.Aesx
{
    internal sealed class AesCbc
    {
        // BlockSize in bits, or 16 in bytes
        private const int BlockSize = 128;

        private AesCbc()
        {

        }

        private static void InitAesCBC(ref Aes aes, AesKey aesKey)
        {
            // set mode
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;

            switch (aesKey)
            {
                case AesKey.Key128:
                    aes.KeySize = (int)AesKey.Key128 * 8;
                    aes.BlockSize = BlockSize;
                    break;

                case AesKey.Key192:
                    aes.KeySize = (int)AesKey.Key192 * 8;
                    aes.BlockSize = BlockSize;
                    break;

                case AesKey.Key256:
                    aes.KeySize = (int)AesKey.Key256 * 8;
                    aes.BlockSize = BlockSize;
                    break;
            }
        }

        // AES CBC Encrypt
        private static byte[] EncryptWithAESCBC(AesKey aesKey, byte[] plaindata, byte[] key)
        {

            byte[] encrypted;
            Aes aes = Aes.Create();
            // init
            InitAesCBC(ref aes, aesKey);
            using (aes)
            {
                // set key and initialization vector
                aes.Key = key;
                aes.IV = aes.IV;

                var ivHexStr = Convert.ToHexString(aes.IV);

                ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

                using (MemoryStream memoryStream = new MemoryStream())
                {
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter streamWriter = new StreamWriter(cryptoStream))
                        {
                            streamWriter.BaseStream.Write(plaindata, 0, plaindata.Length);
                        }

                        encrypted = Lib.Utils.Utils.BufferConcat(Encoding.UTF8.GetBytes(ivHexStr),
                            Encoding.UTF8.GetBytes(Convert.ToHexString(memoryStream.ToArray())));
                    }
                }
            }

            return encrypted;
        }

        // AES CBC Encrypt IO
        private static void EncryptWithAESCBC(AesKey aesKey, Stream plaindata, Stream outEncryptedData, byte[] key)
        {

            Aes aes = Aes.Create();
            // init
            InitAesCBC(ref aes, aesKey);
            using (aes)
            {
                // set key and initialization vector
                aes.Key = key;
                aes.IV = aes.IV;

                var ivHexStr = Convert.ToHexString(aes.IV);

                ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

                using (MemoryStream memoryStream = new MemoryStream())
                {
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                    {
                        // set stream position to 0
                        plaindata.Position = 0;

                        plaindata.CopyTo(cryptoStream);
                    }

                    byte[] encrypted = Lib.Utils.Utils.BufferConcat(Encoding.UTF8.GetBytes(ivHexStr),
                            Encoding.UTF8.GetBytes(Convert.ToHexString(memoryStream.ToArray())));
                    outEncryptedData.Write(encrypted, 0, encrypted.Length);
                }
            }
        }

        // AES CBC Decrypt
        private static byte[] DecryptWithAESCBC(AesKey aesKey, byte[] encryptedData, byte[] key)
        {

            byte[] plaindata;
            Aes aes = Aes.Create();
            // init
            InitAesCBC(ref aes, aesKey);
            using (aes)
            {
                // set key and initialization vector
                aes.Key = key;

                // convert data to hex bytes
                byte[] encryptedDataUnhex = Convert.FromHexString(Encoding.UTF8.GetString(encryptedData));
                byte[] iv = encryptedDataUnhex[0..(BlockSize / 8)];
                byte[] cipherdata = encryptedDataUnhex[(BlockSize / 8)..];

                aes.IV = iv;

                ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                using (MemoryStream memoryStreamCipher = new MemoryStream(cipherdata))
                {
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStreamCipher, decryptor, CryptoStreamMode.Read))
                    {
                        using (MemoryStream memoryStreamOut = new MemoryStream())
                        {
                            cryptoStream.CopyTo(memoryStreamOut);
                            plaindata = memoryStreamOut.ToArray();
                        }
                    }
                }
            }

            return plaindata;
        }

        // AES CBC Decrypt IO
        private static void DecryptWithAESCBC(AesKey aesKey, Stream encryptedData, Stream outPlainData, byte[] key)
        {
            Aes aes = Aes.Create();
            // init
            InitAesCBC(ref aes, aesKey);
            using (aes)
            {
                // set key and initialization vector
                aes.Key = key;

                using (MemoryStream memoryStreamSrc = new MemoryStream())
                {
                    // set stream position to 0
                    encryptedData.Position = 0;

                    encryptedData.CopyTo(memoryStreamSrc);

                    // convert data to hex bytes
                    byte[] encryptedDataUnhex = Convert.FromHexString(Encoding.UTF8.GetString(memoryStreamSrc.ToArray()));
                    byte[] iv = encryptedDataUnhex[0..(BlockSize / 8)];
                    byte[] cipherdata = encryptedDataUnhex[(BlockSize / 8)..];

                    aes.IV = iv;

                    ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                    using (MemoryStream memoryStreamCipher = new MemoryStream(cipherdata))
                    {
                        using (CryptoStream cryptoStream = new CryptoStream(memoryStreamCipher, decryptor, CryptoStreamMode.Read))
                        {
                            cryptoStream.CopyTo(outPlainData);
                        }
                    }
                }
            }
        }

        public static byte[] EncryptWithAES128CBC(byte[] plaindata, byte[] key)
        {
            Validator.Validate(AesKey.Key128, plaindata, key);

            return EncryptWithAESCBC(AesKey.Key128, plaindata, key);
        }

        public static byte[] EncryptWithAES192CBC(byte[] plaindata, byte[] key)
        {
            Validator.Validate(AesKey.Key192, plaindata, key);

            return EncryptWithAESCBC(AesKey.Key192, plaindata, key);
        }

        public static byte[] EncryptWithAES256CBC(byte[] plaindata, byte[] key)
        {
            Validator.Validate(AesKey.Key256, plaindata, key);

            return EncryptWithAESCBC(AesKey.Key256, plaindata, key);
        }

        public static byte[] DecryptWithAES128CBC(byte[] encryptedData, byte[] key)
        {
            Validator.Validate(AesKey.Key128, encryptedData, key);

            return DecryptWithAESCBC(AesKey.Key128, encryptedData, key);
        }

        public static byte[] DecryptWithAES192CBC(byte[] encryptedData, byte[] key)
        {
            Validator.Validate(AesKey.Key192, encryptedData, key);

            return DecryptWithAESCBC(AesKey.Key192, encryptedData, key);
        }

        public static byte[] DecryptWithAES256CBC(byte[] encryptedData, byte[] key)
        {
            Validator.Validate(AesKey.Key256, encryptedData, key);

            return DecryptWithAESCBC(AesKey.Key256, encryptedData, key);
        }

        // io
        public static void EncryptWithAES128CBC(Stream plaindata, Stream outEncryptedData, byte[] key)
        {
            Validator.Validate(AesKey.Key128, plaindata, outEncryptedData, key);

            EncryptWithAESCBC(AesKey.Key128, plaindata, outEncryptedData, key);
        }

        public static void EncryptWithAES192CBC(Stream plaindata, Stream outEncryptedData, byte[] key)
        {
            Validator.Validate(AesKey.Key192, plaindata, outEncryptedData, key);

            EncryptWithAESCBC(AesKey.Key192, plaindata, outEncryptedData, key);
        }

        public static void EncryptWithAES256CBC(Stream plaindata, Stream outEncryptedData, byte[] key)
        {
            Validator.Validate(AesKey.Key256, plaindata, outEncryptedData, key);

            EncryptWithAESCBC(AesKey.Key256, plaindata, outEncryptedData, key);
        }

        public static void DecryptWithAES128CBC(Stream encryptedData, Stream outPlainData, byte[] key)
        {
            Validator.Validate(AesKey.Key128, encryptedData, outPlainData, key);

            DecryptWithAESCBC(AesKey.Key128, encryptedData, outPlainData, key);
        }

        public static void DecryptWithAES192CBC(Stream encryptedData, Stream outPlainData, byte[] key)
        {
            Validator.Validate(AesKey.Key192, encryptedData, outPlainData, key);

            DecryptWithAESCBC(AesKey.Key192, encryptedData, outPlainData, key);
        }

        public static void DecryptWithAES256CBC(Stream encryptedData, Stream outPlainData, byte[] key)
        {
            Validator.Validate(AesKey.Key256, encryptedData, outPlainData, key);

            DecryptWithAESCBC(AesKey.Key256, encryptedData, outPlainData, key);
        }
    }
}
