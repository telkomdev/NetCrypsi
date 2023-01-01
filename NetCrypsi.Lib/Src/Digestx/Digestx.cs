using System;
using System.IO;
using System.Text;

namespace NetCrypsi.Lib.Digestx
{
    public sealed class Digestx
    {
        private Digestx()
        {

        }

        private static byte[] Digest(System.Security.Cryptography.HashAlgorithm hashAlgorithm, Stream data)
        {
            byte[] hashValue = hashAlgorithm.ComputeHash(data);
            return hashValue;
        }

        private static byte[] Digest(System.Security.Cryptography.HashAlgorithm hashAlgorithm, byte[] data)
        {
            byte[] hashValue = hashAlgorithm.ComputeHash(data);
            return hashValue;
        }

        // MD5
        public static byte[] MD5(Stream data)
        {
            byte[] hashValue;
            using (System.Security.Cryptography.MD5 mD5 = System.Security.Cryptography.MD5.Create())
            {
                hashValue = Digest(mD5, data);
            }

            return hashValue;
        }

        public static byte[] MD5(byte[] data)
        {
            byte[] hashValue;
            using (System.Security.Cryptography.MD5 mD5 = System.Security.Cryptography.MD5.Create())
            {
                hashValue = Digest(mD5, data);
            }

            return hashValue;
        }

        public static string MD5Hex(Stream data)
        {
            string hashValue = Convert.ToHexString(MD5(data));
            return hashValue;
        }

        public static string MD5Hex(byte[] data)
        {
            string hashValue = Convert.ToHexString(MD5(data));
            return hashValue;
        }

        // SHA1
        public static byte[] SHA1(Stream data)
        {
            byte[] hashValue;
            using (System.Security.Cryptography.SHA1 sha1 = System.Security.Cryptography.SHA1.Create())
            {
                hashValue = Digest(sha1, data);
            }

            return hashValue;
        }

        public static byte[] SHA1(byte[] data)
        {
            byte[] hashValue;
            using (System.Security.Cryptography.SHA1 sha1 = System.Security.Cryptography.SHA1.Create())
            {
                hashValue = Digest(sha1, data);
            }

            return hashValue;
        }

        public static string SHA1Hex(Stream data)
        {
            string hashValue = Convert.ToHexString(SHA1(data));
            return hashValue;
        }

        public static string SHA1Hex(byte[] data)
        {
            string hashValue = Convert.ToHexString(SHA1(data));
            return hashValue;
        }

        // SHA256
        public static byte[] SHA256(Stream data)
        {
            byte[] hashValue;
            using (System.Security.Cryptography.SHA256 sha256 = System.Security.Cryptography.SHA256.Create())
            {
                hashValue = Digest(sha256, data);
            }

            return hashValue;
        }

        public static byte[] SHA256(byte[] data)
        {
            byte[] hashValue;
            using (System.Security.Cryptography.SHA256 sha256 = System.Security.Cryptography.SHA256.Create())
            {
                hashValue = Digest(sha256, data);
            }

            return hashValue;
        }

        public static string SHA256Hex(Stream data)
        {
            string hashValue = Convert.ToHexString(SHA256(data));
            return hashValue;
        }

        public static string SHA256Hex(byte[] data)
        {
            string hashValue = Convert.ToHexString(SHA256(data));
            return hashValue;
        }

        // SHA384
        public static byte[] SHA384(Stream data)
        {
            byte[] hashValue;
            using (System.Security.Cryptography.SHA384 sha384 = System.Security.Cryptography.SHA384.Create())
            {
                hashValue = Digest(sha384, data);
            }

            return hashValue;
        }

        public static byte[] SHA384(byte[] data)
        {
            byte[] hashValue;
            using (System.Security.Cryptography.SHA384 sha384 = System.Security.Cryptography.SHA384.Create())
            {
                hashValue = Digest(sha384, data);
            }

            return hashValue;
        }

        public static string SHA384Hex(Stream data)
        {
            string hashValue = Convert.ToHexString(SHA384(data));
            return hashValue;
        }

        public static string SHA384Hex(byte[] data)
        {
            string hashValue = Convert.ToHexString(SHA384(data));
            return hashValue;
        }

        // SHA512
        public static byte[] SHA512(Stream data)
        {
            byte[] hashValue;
            using (System.Security.Cryptography.SHA512 sha512 = System.Security.Cryptography.SHA512.Create())
            {
                hashValue = Digest(sha512, data);
            }

            return hashValue;
        }

        public static byte[] SHA512(byte[] data)
        {
            byte[] hashValue;
            using (System.Security.Cryptography.SHA512 sha512 = System.Security.Cryptography.SHA512.Create())
            {
                hashValue = Digest(sha512, data);
            }

            return hashValue;
        }

        public static string SHA512Hex(Stream data)
        {
            string hashValue = Convert.ToHexString(SHA512(data));
            return hashValue;
        }

        public static string SHA512Hex(byte[] data)
        {
            string hashValue = Convert.ToHexString(SHA512(data));
            return hashValue;
        }
    }
}