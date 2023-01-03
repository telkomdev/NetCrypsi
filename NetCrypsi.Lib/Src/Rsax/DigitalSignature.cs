using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Linq;

namespace NetCrypsi.Lib.Rsax
{
    public sealed class DigitalSignature
    {
        private DigitalSignature()
        {

        }

        // SignWithPss, base Signing function with Pss mode
        private static byte[] SignWithPss(byte[] privateKey, byte[] data, HashAlgorithmName algorithmName)
        {
            byte[] signatureBytes;
            using (RSA rsa = RSA.Create())
            {
                rsa.ImportPkcs8PrivateKey(privateKey, out _);
                RSASignaturePadding padding = RSASignaturePadding.Pss;
                signatureBytes = rsa.SignData(data, algorithmName, padding);
            }

            return signatureBytes;
        }

        // SignWithPss, base Signing function with Pss mode that support Stream
        private static byte[] SignWithPss(byte[] privateKey, Stream data, HashAlgorithmName algorithmName)
        {
            byte[] signatureBytes;
            using (RSA rsa = RSA.Create())
            {
                rsa.ImportPkcs8PrivateKey(privateKey, out _);
                RSASignaturePadding padding = RSASignaturePadding.Pss;
                signatureBytes = rsa.SignData(data, algorithmName, padding);
            }

            return signatureBytes;
        }

        // VerifySignatureWithPss, base Verify signature function with Pss mode
        private static bool VerifySignatureWithPss(byte[] publicKey, byte[] signature, byte[] data, HashAlgorithmName algorithmName)
        {
            bool signatureValid;
            using (RSA rsa = RSA.Create())
            {
                rsa.ImportRSAPublicKey(publicKey, out _);
                RSASignaturePadding padding = RSASignaturePadding.Pss;
                signatureValid = rsa.VerifyData(data, signature, algorithmName, padding);
            }

            return signatureValid;
        }

        // VerifySignatureWithPss, base Verify signature function with Pss mode that support Stream
        private static bool VerifySignatureWithPss(byte[] publicKey, byte[] signature, Stream data, HashAlgorithmName algorithmName)
        {
            bool signatureValid;
            using (RSA rsa = RSA.Create())
            {
                rsa.ImportRSAPublicKey(publicKey, out _);
                RSASignaturePadding padding = RSASignaturePadding.Pss;
                signatureValid = rsa.VerifyData(data, signature, algorithmName, padding);
            }

            return signatureValid;
        }

        // signing
        public static byte[] SignWithPssMD5(byte[] privateKey, byte[] data) => SignWithPss(privateKey, data, HashAlgorithmName.MD5);

        public static byte[] SignWithPssSHA1(byte[] privateKey, byte[] data) => SignWithPss(privateKey, data, HashAlgorithmName.SHA1);

        public static byte[] SignWithPssSHA256(byte[] privateKey, byte[] data) => SignWithPss(privateKey, data, HashAlgorithmName.SHA256);

        public static byte[] SignWithPssSHA384(byte[] privateKey, byte[] data) => SignWithPss(privateKey, data, HashAlgorithmName.SHA384);

        public static byte[] SignWithPssSHA512(byte[] privateKey, byte[] data) => SignWithPss(privateKey, data, HashAlgorithmName.SHA512);

        // signing Stream
        public static byte[] SignWithPssMD5(byte[] privateKey, Stream data) => SignWithPss(privateKey, data, HashAlgorithmName.MD5);

        public static byte[] SignWithPssSHA1(byte[] privateKey, Stream data) => SignWithPss(privateKey, data, HashAlgorithmName.SHA1);

        public static byte[] SignWithPssSHA256(byte[] privateKey, Stream data) => SignWithPss(privateKey, data, HashAlgorithmName.SHA256);

        public static byte[] SignWithPssSHA384(byte[] privateKey, Stream data) => SignWithPss(privateKey, data, HashAlgorithmName.SHA384);

        public static byte[] SignWithPssSHA512(byte[] privateKey, Stream data) => SignWithPss(privateKey, data, HashAlgorithmName.SHA512);

        // Verifying
        public static bool VerifySignatureWithPssMD5(byte[] publicKey, byte[] signature, byte[] data) => VerifySignatureWithPss(publicKey,
                                                                                                        signature, data, HashAlgorithmName.MD5);

        public static bool VerifySignatureWithPssSHA1(byte[] publicKey, byte[] signature, byte[] data) => VerifySignatureWithPss(publicKey,
                                                                                                        signature, data, HashAlgorithmName.SHA1);

        public static bool VerifySignatureWithPssSHA256(byte[] publicKey, byte[] signature, byte[] data) => VerifySignatureWithPss(publicKey,
                                                                                                        signature, data, HashAlgorithmName.SHA256);

        public static bool VerifySignatureWithPssSHA384(byte[] publicKey, byte[] signature, byte[] data) => VerifySignatureWithPss(publicKey,
                                                                                                        signature, data, HashAlgorithmName.SHA384);

        public static bool VerifySignatureWithPssSHA512(byte[] publicKey, byte[] signature, byte[] data) => VerifySignatureWithPss(publicKey,
                                                                                                        signature, data, HashAlgorithmName.SHA512);

        // Verifying Stream
        public static bool VerifySignatureWithPssMD5(byte[] publicKey, byte[] signature, Stream data) => VerifySignatureWithPss(publicKey,
                                                                                                        signature, data, HashAlgorithmName.MD5);

        public static bool VerifySignatureWithPssSHA1(byte[] publicKey, byte[] signature, Stream data) => VerifySignatureWithPss(publicKey,
                                                                                                        signature, data, HashAlgorithmName.SHA1);

        public static bool VerifySignatureWithPssSHA256(byte[] publicKey, byte[] signature, Stream data) => VerifySignatureWithPss(publicKey,
                                                                                                        signature, data, HashAlgorithmName.SHA256);

        public static bool VerifySignatureWithPssSHA384(byte[] publicKey, byte[] signature, Stream data) => VerifySignatureWithPss(publicKey,
                                                                                                        signature, data, HashAlgorithmName.SHA384);

        public static bool VerifySignatureWithPssSHA512(byte[] publicKey, byte[] signature, Stream data) => VerifySignatureWithPss(publicKey,
                                                                                                        signature, data, HashAlgorithmName.SHA512);
    }
}