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
                Console.WriteLine(padding.OaepHashAlgorithm);
                Console.WriteLine(padding.Mode);
                encryptedDataBytes = rsa.Encrypt(plainData, padding);
            }

            return encryptedDataBytes;
        }

        // DecryptWithOaep, base decryption function with OAEP mode
        private static byte[] DecryptWithOaep(byte[] privateKey, byte[] encryptedData, HashAlgorithmName algorithmName)
        {
            byte[] encryptedDataBytes;
            using (RSA rsa = RSA.Create())
            {
                rsa.ImportPkcs8PrivateKey(privateKey, out _);
                RSAEncryptionPadding padding = RSAEncryptionPadding.CreateOaep(algorithmName);
                encryptedDataBytes = rsa.Decrypt(encryptedData, padding);
            }

            return encryptedDataBytes;
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
    }
}