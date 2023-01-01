using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace NetCrypsi.Lib.Hmacx
{
    public sealed class Hmacx
    {
        private const int MinMaxKeyLength = 32;

        private Hmacx()
        {

        }

        private static void Validate(byte[] key)
        {
            if (key.Length < MinMaxKeyLength)
            {
                throw new ArgumentException(string.Format("min key length must be {0}", MinMaxKeyLength));
            }
        }

        private static byte[] Digest(System.Security.Cryptography.HMAC hmac, Stream data)
        {
            byte[] hashValue = hmac.ComputeHash(data);
            return hashValue;
        }

        private static byte[] Digest(System.Security.Cryptography.HMAC hmac, byte[] data)
        {
            byte[] hashValue = hmac.ComputeHash(data);
            return hashValue;
        }

        // MD5
        public static byte[] MD5(byte[] key, Stream data)
        {
            Validate(key);

            byte[] hashValue;
            using (System.Security.Cryptography.HMACMD5 mD5 = new System.Security.Cryptography.HMACMD5(key))
            {
                hashValue = Digest(mD5, data);
            }

            return hashValue;
        }

        public static byte[] MD5(byte[] key, byte[] data)
        {
            Validate(key);
            
            byte[] hashValue;
            using (System.Security.Cryptography.HMACMD5 mD5 = new System.Security.Cryptography.HMACMD5(key))
            {
                hashValue = Digest(mD5, data);
            }

            return hashValue;
        }

        public static string MD5Hex(byte[] key, Stream data)
        {
            Validate(key);

            string hashValue = Convert.ToHexString(MD5(key, data));
            return hashValue;
        }

        public static string MD5Hex(byte[] key, byte[] data)
        {
            Validate(key);

            string hashValue = Convert.ToHexString(MD5(key, data));
            return hashValue;
        }

        // SHA1
        public static byte[] SHA1(byte[] key, Stream data)
        {
            Validate(key);

            byte[] hashValue;
            using (System.Security.Cryptography.HMACSHA1 sha1 = new System.Security.Cryptography.HMACSHA1(key))
            {
                hashValue = Digest(sha1, data);
            }

            return hashValue;
        }

        public static byte[] SHA1(byte[] key, byte[] data)
        {
            Validate(key);

            byte[] hashValue;
            using (System.Security.Cryptography.HMACSHA1 sha1 = new System.Security.Cryptography.HMACSHA1(key))
            {
                hashValue = Digest(sha1, data);
            }

            return hashValue;
        }

        public static string SHA1Hex(byte[] key,Stream data)
        {
            Validate(key);

            string hashValue = Convert.ToHexString(SHA1(key, data));
            return hashValue;
        }

        public static string SHA1Hex(byte[] key,byte[] data)
        {
            Validate(key);

            string hashValue = Convert.ToHexString(SHA1(key, data));
            return hashValue;
        }

        // SHA256
        public static byte[] SHA256(byte[] key, Stream data)
        {
            Validate(key);

            byte[] hashValue;
            using (System.Security.Cryptography.HMACSHA256 sha256 = new System.Security.Cryptography.HMACSHA256(key))
            {
                hashValue = Digest(sha256, data);
            }

            return hashValue;
        }

        public static byte[] SHA256(byte[] key, byte[] data)
        {
            Validate(key);

            byte[] hashValue;
            using (System.Security.Cryptography.HMACSHA256 sha256 = new System.Security.Cryptography.HMACSHA256(key))
            {
                hashValue = Digest(sha256, data);
            }

            return hashValue;
        }

        public static string SHA256Hex(byte[] key, Stream data)
        {
            Validate(key);

            string hashValue = Convert.ToHexString(SHA256(key, data));
            return hashValue;
        }

        public static string SHA256Hex(byte[] key, byte[] data)
        {
            Validate(key);

            string hashValue = Convert.ToHexString(SHA256(key, data));
            return hashValue;
        }

        // SHA384
        public static byte[] SHA384(byte[] key, Stream data)
        {
            Validate(key);

            byte[] hashValue;
            using (System.Security.Cryptography.HMACSHA384 sha384 = new System.Security.Cryptography.HMACSHA384(key))
            {
                hashValue = Digest(sha384, data);
            }

            return hashValue;
        }

        public static byte[] SHA384(byte[] key, byte[] data)
        {
            Validate(key);

            byte[] hashValue;
            using (System.Security.Cryptography.HMACSHA384 sha384 = new System.Security.Cryptography.HMACSHA384(key))
            {
                hashValue = Digest(sha384, data);
            }

            return hashValue;
        }

        public static string SHA384Hex(byte[] key, Stream data)
        {
            Validate(key);

            string hashValue = Convert.ToHexString(SHA384(key, data));
            return hashValue;
        }

        public static string SHA384Hex(byte[] key, byte[] data)
        {
            Validate(key);

            string hashValue = Convert.ToHexString(SHA384(key, data));
            return hashValue;
        }

        // SHA512
        public static byte[] SHA512(byte[] key, Stream data)
        {
            Validate(key);

            byte[] hashValue;
            using (System.Security.Cryptography.HMACSHA512 sha512 = new System.Security.Cryptography.HMACSHA512(key))
            {
                hashValue = Digest(sha512, data);
            }

            return hashValue;
        }

        public static byte[] SHA512(byte[] key, byte[] data)
        {
            Validate(key);

            byte[] hashValue;
            using (System.Security.Cryptography.HMACSHA512 sha512 = new System.Security.Cryptography.HMACSHA512(key))
            {
                hashValue = Digest(sha512, data);
            }

            return hashValue;
        }

        public static string SHA512Hex(byte[] key, Stream data)
        {
            Validate(key);

            string hashValue = Convert.ToHexString(SHA512(key, data));
            return hashValue;
        }

        public static string SHA512Hex(byte[] key, byte[] data)
        {
            Validate(key);
            
            string hashValue = Convert.ToHexString(SHA512(key, data));
            return hashValue;
        }
    }
}