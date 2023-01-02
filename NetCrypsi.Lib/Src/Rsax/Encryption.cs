using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Linq;

namespace NetCrypsi.Lib.Rsax
{
    public sealed class Encryption
    {
        private Encryption()
        {

        }

        // EncryptWithOaep, base encryption function with OAEP mode
        private static byte[] EncryptWithOaep(byte[] publicKey, byte[] plainData, HashAlgorithmName algorithmName)
        {
            byte[] encryptedDataBytes;
            using (RSA rsa = RSA.Create())
            {
                rsa.ImportRSAPublicKey(publicKey, out _);
                RSAEncryptionPadding padding = RSAEncryptionPadding.CreateOaep(algorithmName);
                encryptedDataBytes = rsa.Encrypt(plainData, padding);
            }

            return encryptedDataBytes;
        }

        // EncryptWithOaep, base encryption function with OAEP mode that support Stream
        private static void EncryptWithOaep(byte[] publicKey, Stream plainData, Stream encryptedData, HashAlgorithmName algorithmName)
        {
            using (RSA rsa = RSA.Create())
            {
                rsa.ImportRSAPublicKey(publicKey, out _);
                RSAEncryptionPadding padding = RSAEncryptionPadding.CreateOaep(algorithmName);

                using (MemoryStream plainDataMemStream = new MemoryStream())
                {
                    // set stream position to 0
                    plainData.Position = 0;

                    plainData.CopyTo(plainDataMemStream);

                    // encrypt data
                    byte[] encryptedDataBytes = rsa.Encrypt(plainDataMemStream.ToArray(), padding);
                    encryptedData.Write(encryptedDataBytes, 0, encryptedDataBytes.Length);
                }
            }
        }

        // DecryptWithOaep, base decryption function with OAEP mode
        private static byte[] DecryptWithOaep(byte[] privateKey, byte[] encryptedData, HashAlgorithmName algorithmName)
        {
            byte[] decryptedDataBytes;
            using (RSA rsa = RSA.Create())
            {
                rsa.ImportPkcs8PrivateKey(privateKey, out _);
                RSAEncryptionPadding padding = RSAEncryptionPadding.CreateOaep(algorithmName);
                decryptedDataBytes = rsa.Decrypt(encryptedData, padding);
            }

            return decryptedDataBytes;
        }

        // DecryptWithOaep, base decryption function with OAEP mode that support Stream
        private static void DecryptWithOaep(byte[] privateKey, Stream encryptedData, Stream plainData, HashAlgorithmName algorithmName)
        {
            using (RSA rsa = RSA.Create())
            {
                rsa.ImportPkcs8PrivateKey(privateKey, out _);
                RSAEncryptionPadding padding = RSAEncryptionPadding.CreateOaep(algorithmName);

                using (MemoryStream encryptedDataMemStream = new MemoryStream())
                {
                    // set stream position to 0
                    encryptedData.Position = 0;

                    encryptedData.CopyTo(encryptedDataMemStream);

                    // encrypt data
                    byte[] decryptedDataBytes = rsa.Decrypt(encryptedDataMemStream.ToArray(), padding);
                    plainData.Write(decryptedDataBytes, 0, decryptedDataBytes.Length);
                }
            }
        }

        private static void Validate(byte[] key, byte[] data, HashAlgorithmName algorithmName)
        {
            if (key == null || key.Length <= 0)
            {
                throw new ArgumentException("invalid private or public key");
            }

            if (data == null)
            {
                throw new ArgumentException("data cannot be null");
            }

            if (algorithmName == null)
            {
                throw new ArgumentException("algorithmName cannot be null");
            }
        }

        // Encrypt
        public static byte[] EncryptWithOaepMD5(byte[] publicKey, byte[] plainData)
        {
            return EncryptWithOaep(publicKey, plainData, HashAlgorithmName.MD5);
        }

        public static byte[] EncryptWithOaepSHA1(byte[] publicKey, byte[] plainData)
        {
            return EncryptWithOaep(publicKey, plainData, HashAlgorithmName.SHA1);
        }

        public static byte[] EncryptWithOaepSHA256(byte[] publicKey, byte[] plainData)
        {
            return EncryptWithOaep(publicKey, plainData, HashAlgorithmName.SHA256);
        }

        public static byte[] EncryptWithOaepSHA384(byte[] publicKey, byte[] plainData)
        {
            return EncryptWithOaep(publicKey, plainData, HashAlgorithmName.SHA384);
        }

        public static byte[] EncryptWithOaepSHA512(byte[] publicKey, byte[] plainData)
        {
            return EncryptWithOaep(publicKey, plainData, HashAlgorithmName.SHA512);
        }

        // Encrypt Stream
        public static void EncryptWithOaepMD5(byte[] publicKey, Stream plainData, Stream encryptedData)
        {
            EncryptWithOaep(publicKey, plainData, encryptedData, HashAlgorithmName.MD5);
        }

        // Decrypt
        public static byte[] DecryptWithOaepMD5(byte[] privateKey, byte[] encryptedData)
        {
            return DecryptWithOaep(privateKey, encryptedData, HashAlgorithmName.MD5);
        }

        public static byte[] DecryptWithOaepSHA1(byte[] privateKey, byte[] encryptedData)
        {
            return DecryptWithOaep(privateKey, encryptedData, HashAlgorithmName.SHA1);
        }

        public static byte[] DecryptWithOaepSHA256(byte[] privateKey, byte[] encryptedData)
        {
            return DecryptWithOaep(privateKey, encryptedData, HashAlgorithmName.SHA256);
        }

        public static byte[] DecryptWithOaepSHA384(byte[] privateKey, byte[] encryptedData)
        {
            return DecryptWithOaep(privateKey, encryptedData, HashAlgorithmName.SHA384);
        }

        public static byte[] DecryptWithOaepSHA512(byte[] privateKey, byte[] encryptedData)
        {
            return DecryptWithOaep(privateKey, encryptedData, HashAlgorithmName.SHA512);
        }

        // Decrypt Stream
        public static void DecryptWithOaepMD5(byte[] privateKey, Stream encryptedData, Stream plainData)
        {
            DecryptWithOaep(privateKey, encryptedData, plainData, HashAlgorithmName.MD5);
        }
    }
}