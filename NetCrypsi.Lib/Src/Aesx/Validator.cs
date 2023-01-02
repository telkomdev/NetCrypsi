using System;

namespace NetCrypsi.Lib.Aesx
{
    internal sealed class Validator
    {
        private Validator()
        {

        }

        public static void Validate(AesKey aesKey, byte[] data, byte[] key)
        {
            if (data == null || data.Length <= 0)
            {
                throw new ArgumentNullException("plain data");
            }

            if (key == null || key.Length <= 0)
            {
                throw new ArgumentNullException("Key");
            }

            switch (aesKey)
            {
                case AesKey.Key128:
                    if (key.Length != (int)AesKey.Key128)
                    {
                        throw new ArgumentException("aes 128 must have 16 bytes key size");
                    }
                    break;

                case AesKey.Key192:
                    if (key.Length != (int)AesKey.Key192)
                    {
                        throw new ArgumentException("aes 192 must have 24 bytes key size");
                    }
                    break;

                case AesKey.Key256:
                    if (key.Length != (int)AesKey.Key256)
                    {
                        throw new ArgumentException("aes 256 must have 32 bytes key size");
                    }
                    break;
            }
        }

        public static void Validate(AesKey aesKey, Stream srcData, Stream dstData, byte[] key)
        {
            if (srcData == null || srcData.Length <= 0)
            {
                throw new ArgumentNullException("src data");
            }

            if (dstData == null)
            {
                throw new ArgumentNullException("dst data");
            }

            if (key == null || key.Length <= 0)
            {
                throw new ArgumentNullException("Key");
            }

            switch (aesKey)
            {
                case AesKey.Key128:
                    if (key.Length != (int)AesKey.Key128)
                    {
                        throw new ArgumentException("aes 128 must have 16 bytes key size");
                    }
                    break;

                case AesKey.Key192:
                    if (key.Length != (int)AesKey.Key192)
                    {
                        throw new ArgumentException("aes 192 must have 24 bytes key size");
                    }
                    break;

                case AesKey.Key256:
                    if (key.Length != (int)AesKey.Key256)
                    {
                        throw new ArgumentException("aes 256 must have 32 bytes key size");
                    }
                    break;
            }
        }
    }
}