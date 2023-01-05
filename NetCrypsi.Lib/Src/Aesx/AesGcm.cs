using System;
using System.IO;
using System.Text;

namespace NetCrypsi.Lib.Aesx
{
    internal sealed class AesGcm
    {
        private AesGcm()
        {

        }

        // EncryptWithAESGCM AES GCM base encrypt function
        private static byte[] EncryptWithAESGCM(AesKey aesKey, byte[] plaindata, byte[] key)
        {
            byte[] encrypted;
            using (System.Security.Cryptography.AesGcm aesGcm = new System.Security.Cryptography.AesGcm(key))
            {
                if (!System.Security.Cryptography.AesGcm.IsSupported)
                {
                    throw new Exception("aes gcm is not supported on the current platform");
                }

                int nonceSize = System.Security.Cryptography.AesGcm.NonceByteSizes.MaxSize;
                int tagSize = System.Security.Cryptography.AesGcm.TagByteSizes.MaxSize;

                byte[] cipherDataBuffer = new byte[plaindata.Length];
                byte[] tagBuffer = new byte[tagSize];
                // generate unique nonce

                byte[] nonce = System.Security.Cryptography.RandomNumberGenerator.GetBytes(nonceSize);

                aesGcm.Encrypt(nonce, plaindata, cipherDataBuffer, tagBuffer);

                // convert nonce to hex string format
                string nonceHexStr = Convert.ToHexString(nonce);

                // convert tagBuffer to hex string format
                string tagBufferHexStr = Convert.ToHexString(tagBuffer);

                // convert cipherDataBuffer to hex string format
                string cipherDataBufferHexStr = Convert.ToHexString(cipherDataBuffer);

                // append nonce, cipher buffer and tag buffer
                encrypted = Lib.Utils.Utils.BufferConcat(Encoding.UTF8.GetBytes(nonceHexStr),
                            Encoding.UTF8.GetBytes(cipherDataBufferHexStr));
                encrypted = Lib.Utils.Utils.BufferConcat(encrypted, Encoding.UTF8.GetBytes(tagBufferHexStr));
            }

            return encrypted;
        }

        // EncryptWithAESGCM AES GCM base encrypt function that support stream
        private static void EncryptWithAESGCM(AesKey aesKey, Stream plaindata, Stream outEncryptedData, byte[] key)
        {
            using (System.Security.Cryptography.AesGcm aesGcm = new System.Security.Cryptography.AesGcm(key))
            {
                if (!System.Security.Cryptography.AesGcm.IsSupported)
                {
                    throw new Exception("aes gcm is not supported on the current platform");
                }

                int nonceSize = System.Security.Cryptography.AesGcm.NonceByteSizes.MaxSize;
                int tagSize = System.Security.Cryptography.AesGcm.TagByteSizes.MaxSize;

                // generate unique nonce

                byte[] nonce = System.Security.Cryptography.RandomNumberGenerator.GetBytes(nonceSize);

                byte[] plainDataFromStream;
                using (MemoryStream memoryStream = new MemoryStream())
                {
                    // set stream position to 0
                    plaindata.Position = 0;
                    plaindata.CopyTo(memoryStream);

                    plainDataFromStream = memoryStream.ToArray();
                }

                byte[] cipherDataBuffer = new byte[plainDataFromStream.Length];

                byte[] tagBuffer = new byte[tagSize];
                aesGcm.Encrypt(nonce, plainDataFromStream, cipherDataBuffer, tagBuffer);

                // convert nonce to hex string format
                string nonceHexStr = Convert.ToHexString(nonce);

                // convert tagBuffer to hex string format
                string tagBufferHexStr = Convert.ToHexString(tagBuffer);

                // convert cipherDataBuffer to hex string format
                string cipherDataBufferHexStr = Convert.ToHexString(cipherDataBuffer);

                // append nonce, cipher buffer and tag buffer
                byte[] encrypted = Lib.Utils.Utils.BufferConcat(Encoding.UTF8.GetBytes(nonceHexStr),
                            Encoding.UTF8.GetBytes(cipherDataBufferHexStr));
                encrypted = Lib.Utils.Utils.BufferConcat(encrypted, Encoding.UTF8.GetBytes(tagBufferHexStr));

                outEncryptedData.Write(encrypted, 0, encrypted.Length);
            }
        }

        // DecryptWithAESGCM AES GCM base decrypt function
        private static byte[] DecryptWithAESGCM(AesKey aesKey, byte[] encryptedData, byte[] key)
        {
            byte[] plainData;
            using (System.Security.Cryptography.AesGcm aesGcm = new System.Security.Cryptography.AesGcm(key))
            {
                if (!System.Security.Cryptography.AesGcm.IsSupported)
                {
                    throw new Exception("aes gcm is not supported on the current platform");
                }

                int nonceSize = System.Security.Cryptography.AesGcm.NonceByteSizes.MaxSize;
                int tagSize = System.Security.Cryptography.AesGcm.TagByteSizes.MaxSize;

                byte[] encryptedDataUnhex = Convert.FromHexString(Encoding.UTF8.GetString(encryptedData));

                // slice every part
                byte[] nonce = encryptedDataUnhex[0..nonceSize];
                byte[] cipherdata = encryptedDataUnhex[nonceSize..(encryptedDataUnhex.Length - tagSize)];
                byte[] tagBuffer = encryptedDataUnhex[(encryptedDataUnhex.Length - tagSize)..];

                byte[] plainDataBufferOut = new byte[cipherdata.Length];

                aesGcm.Decrypt(nonce, cipherdata, tagBuffer, plainDataBufferOut);
                plainData = plainDataBufferOut;
            }

            return plainData;
        }

        // DecryptWithAESGCM AES GCM base decrypt function
        private static void DecryptWithAESGCM(AesKey aesKey, Stream encryptedData, Stream outPlainData, byte[] key)
        {
            using (System.Security.Cryptography.AesGcm aesGcm = new System.Security.Cryptography.AesGcm(key))
            {
                if (!System.Security.Cryptography.AesGcm.IsSupported)
                {
                    throw new Exception("aes gcm is not supported on the current platform");
                }

                int nonceSize = System.Security.Cryptography.AesGcm.NonceByteSizes.MaxSize;
                int tagSize = System.Security.Cryptography.AesGcm.TagByteSizes.MaxSize;

                byte[] encryptedDataFromStream;
                using (MemoryStream memoryStreamCipher = new MemoryStream())
                {
                    // set encryptedData position to 0
                    encryptedData.Position = 0;
                    encryptedData.CopyTo(memoryStreamCipher);

                    encryptedDataFromStream = memoryStreamCipher.ToArray();
                }

                // unhex the stream
                byte[] encryptedDataUnhex = Convert.FromHexString(Encoding.UTF8.GetString(encryptedDataFromStream));

                // slice every part
                byte[] nonce = encryptedDataUnhex[0..nonceSize];
                byte[] cipherdata = encryptedDataUnhex[nonceSize..(encryptedDataUnhex.Length - tagSize)];
                byte[] tagBuffer = encryptedDataUnhex[(encryptedDataUnhex.Length - tagSize)..];

                byte[] plainDataBufferOut = new byte[cipherdata.Length];

                aesGcm.Decrypt(nonce, cipherdata, tagBuffer, plainDataBufferOut);
                outPlainData.Write(plainDataBufferOut, 0, plainDataBufferOut.Length);
            }
        }

        public static byte[] EncryptWithAES128GCM(byte[] plaindata, byte[] key)
        {
            Validator.Validate(AesKey.Key128, plaindata, key);

            return EncryptWithAESGCM(AesKey.Key128, plaindata, key);
        }

        public static byte[] EncryptWithAES192GCM(byte[] plaindata, byte[] key)
        {
            Validator.Validate(AesKey.Key192, plaindata, key);

            return EncryptWithAESGCM(AesKey.Key192, plaindata, key);
        }

        public static byte[] EncryptWithAES256GCM(byte[] plaindata, byte[] key)
        {
            Validator.Validate(AesKey.Key256, plaindata, key);

            return EncryptWithAESGCM(AesKey.Key256, plaindata, key);
        }

        public static byte[] DecryptWithAES128GCM(byte[] encryptedData, byte[] key)
        {
            Validator.Validate(AesKey.Key128, encryptedData, key);

            return DecryptWithAESGCM(AesKey.Key128, encryptedData, key);
        }

        public static byte[] DecryptWithAES192GCM(byte[] encryptedData, byte[] key)
        {
            Validator.Validate(AesKey.Key192, encryptedData, key);

            return DecryptWithAESGCM(AesKey.Key192, encryptedData, key);
        }

        public static byte[] DecryptWithAES256GCM(byte[] encryptedData, byte[] key)
        {
            Validator.Validate(AesKey.Key256, encryptedData, key);

            return DecryptWithAESGCM(AesKey.Key256, encryptedData, key);
        }

        // io
        public static void EncryptWithAES128GCM(Stream plaindata, Stream outEncryptedData, byte[] key)
        {
            Validator.Validate(AesKey.Key128, plaindata, outEncryptedData, key);

            EncryptWithAESGCM(AesKey.Key128, plaindata, outEncryptedData, key);
        }

        public static void EncryptWithAES192GCM(Stream plaindata, Stream outEncryptedData, byte[] key)
        {
            Validator.Validate(AesKey.Key192, plaindata, outEncryptedData, key);

            EncryptWithAESGCM(AesKey.Key192, plaindata, outEncryptedData, key);
        }

        public static void EncryptWithAES256GCM(Stream plaindata, Stream outEncryptedData, byte[] key)
        {
            Validator.Validate(AesKey.Key256, plaindata, outEncryptedData, key);

            EncryptWithAESGCM(AesKey.Key256, plaindata, outEncryptedData, key);
        }

        public static void DecryptWithAES128GCM(Stream encryptedData, Stream outPlainData, byte[] key)
        {
            Validator.Validate(AesKey.Key128, encryptedData, outPlainData, key);

            DecryptWithAESGCM(AesKey.Key128, encryptedData, outPlainData, key);
        }

        public static void DecryptWithAES192GCM(Stream encryptedData, Stream outPlainData, byte[] key)
        {
            Validator.Validate(AesKey.Key192, encryptedData, outPlainData, key);

            DecryptWithAESGCM(AesKey.Key192, encryptedData, outPlainData, key);
        }

        public static void DecryptWithAES256GCM(Stream encryptedData, Stream outPlainData, byte[] key)
        {
            Validator.Validate(AesKey.Key256, encryptedData, outPlainData, key);

            DecryptWithAESGCM(AesKey.Key256, encryptedData, outPlainData, key);
        }
    }
}