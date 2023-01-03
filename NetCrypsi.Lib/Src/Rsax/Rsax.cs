using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Linq;

namespace NetCrypsi.Lib.Rsax
{
    public sealed class Rsax
    {
        // KeySize1Kb 1024
        public const int KeySize1Kb = 1 << 10; // 1024

        // KeySize2Kb 2048
        public const int KeySize2Kb = 1 << 11; // 2048

        // KeySize4Kb 4096
        public const int KeySize4Kb = 1 << 12; // 4096

        private byte[]? privateKeyPKCS8Bytes;

        private byte[]? privateKeyPKCS1Bytes;

        private byte[]? publicKeyPKCS1Bytes;

        private string? privateKeyPKCS8String;

        private string? privateKeyPKCS1String;

        private string? publicKeyPKCS1String;

        private Rsax()
        {

        }

        // convert rsa public key from PKCS1 format to x509
        // openssl rsa -RSAPublicKey_in -in public.key -pubout

        // convert rsa private key from PKCS1 format to PKCS8
        // openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in private_pkcs1.key -out private_key_pkcs82.key
        public static Rsax Create(int rsaKeySize)
        {
            if (!new int[] { KeySize1Kb, KeySize2Kb, KeySize4Kb }.Contains(rsaKeySize))
                throw new ArgumentException(string.Format("rsaKeySize must be {0}, {1} or {2}", KeySize1Kb, KeySize2Kb, KeySize4Kb));
            Rsax rsax = new Rsax();

            using (RSA rsa = RSA.Create(rsaKeySize))
            {
                byte[] privateKeyPkcs8Bytes = rsa.ExportPkcs8PrivateKey();
                byte[] privateKeyPkcs1Bytes = rsa.ExportRSAPrivateKey();
                byte[] publicKeyPkcs1Bytes = rsa.ExportRSAPublicKey();

                string privateKeyPkcs8Str = Convert.ToBase64String(privateKeyPkcs8Bytes);
                string privateKeyPkcs1Str = Convert.ToBase64String(privateKeyPkcs1Bytes);
                string publicKeyPkcs1Str = Convert.ToBase64String(publicKeyPkcs1Bytes);

                rsax.privateKeyPKCS8Bytes = privateKeyPkcs8Bytes;
                rsax.privateKeyPKCS1Bytes = privateKeyPkcs1Bytes;

                rsax.publicKeyPKCS1Bytes = publicKeyPkcs1Bytes;

                rsax.privateKeyPKCS8String = privateKeyPkcs8Str;
                rsax.privateKeyPKCS1String = privateKeyPkcs1Str;

                rsax.publicKeyPKCS1String = publicKeyPkcs1Str;
            }

            return rsax;
        }


        public byte[]? PrivateKeyPKCS8Bytes() => privateKeyPKCS8Bytes;

        public byte[]? PrivateKeyPKCS1Bytes() => privateKeyPKCS1Bytes;

        public byte[]? PublicKeyPKCS1Bytes() => publicKeyPKCS1Bytes;

        // Export private key in PKCS8 format to PEM stream
        public void ExportPKCS8PrivateKeyToStreamPem(Stream stream)
        {
            stream.Write(Encoding.UTF8.GetBytes("-----BEGIN PRIVATE KEY-----\n"));
            // Output as Base64 with lines chopped at 64 characters
            for (var i = 0; i < privateKeyPKCS8String!.Length; i += 64)
            {
                stream.Write(
                    Encoding.UTF8.GetBytes(privateKeyPKCS8String!),
                    i,
                Math.Min(64, privateKeyPKCS8String!.Length - i));

                stream.Write(Encoding.UTF8.GetBytes("\n"));
            }
            stream.Write(Encoding.UTF8.GetBytes("-----END PRIVATE KEY-----"));
        }

        // Export private key in PKCS1 format to PEM stream
        public void ExportPKCS1PrivateKeyToStreamPem(Stream stream)
        {
            stream.Write(Encoding.UTF8.GetBytes("-----BEGIN RSA PRIVATE KEY-----\n"));
            // Output as Base64 with lines chopped at 64 characters
            for (var i = 0; i < privateKeyPKCS1String!.Length; i += 64)
            {
                stream.Write(
                    Encoding.UTF8.GetBytes(privateKeyPKCS1String!),
                    i,
                Math.Min(64, privateKeyPKCS1String!.Length - i));

                stream.Write(Encoding.UTF8.GetBytes("\n"));
            }
            stream.Write(Encoding.UTF8.GetBytes("-----END RSA PRIVATE KEY-----"));
        }

        // Export public key in PKCS1 format to PEM stream
        public void ExportPKCS1PublicKeyToStreamPem(Stream stream)
        {
            stream.Write(Encoding.UTF8.GetBytes("-----BEGIN RSA PUBLIC KEY-----\n"));
            // Output as Base64 with lines chopped at 64 characters
            for (var i = 0; i < publicKeyPKCS1String!.Length; i += 64)
            {
                stream.Write(
                    Encoding.UTF8.GetBytes(publicKeyPKCS1String!),
                    i,
                Math.Min(64, publicKeyPKCS1String!.Length - i));

                stream.Write(Encoding.UTF8.GetBytes("\n"));
            }
            stream.Write(Encoding.UTF8.GetBytes("-----END RSA PUBLIC KEY-----"));
        }

        // Export private key in PKCS8 format to Hexadecimal string
        public string ExportPKCS8PrivateKeyToHexStr() => Convert.ToHexString(privateKeyPKCS8Bytes!);

        // Export private key in PKCS1 format to Hexadecimal string
        public string ExportPKCS1PrivateKeyToHexStr() => Convert.ToHexString(privateKeyPKCS1Bytes!);

        // Export public key in PKCS1 format to Hexadecimal string
        public string ExportPKCS1PublicKeyToHexStr() => Convert.ToHexString(publicKeyPKCS1Bytes!);

        // Load any private or public key from hex string
        public static byte[] LoadKeyFromHexStr(string keyHexStr) => Convert.FromHexString(keyHexStr);

        // Load any private or public key from PEM 
        public static byte[] LoadKeyFromPem(Stream stream)
        {
            byte[] keyBytes;
            using (MemoryStream memoryStream = new MemoryStream())
            {
                using (StreamReader streamReader = new StreamReader(stream))
                {
                    string? line;

                    while ((line = streamReader.ReadLine()) != null)
                    {
                        if (line.Contains("BEGIN") || line.Contains("END"))
                        {
                            continue;
                        }

                        // additional guards, if the line still contains \n and \r
                        line = line.Replace("\n", "").Replace("\r", "");

                        memoryStream.Write(Convert.FromBase64String(line));
                    }
                }

                keyBytes = memoryStream.ToArray();
            }

            return keyBytes;
        }
    }
}