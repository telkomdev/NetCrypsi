using System;
using System.IO;
using System.Text;

namespace NetCrypsi.Lib.Aesx
{
    public sealed class AesGcm
    {
        private AesGcm()
        {

        }

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

                Console.WriteLine(string.Format("nonce size: {0}", nonceSize));
                Console.WriteLine(string.Format("tag size: {0}", tagSize));

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
    }
}