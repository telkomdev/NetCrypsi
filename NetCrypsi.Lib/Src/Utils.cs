using System;

namespace NetCrypsi.Lib.Utils
{
    internal sealed class Utils
    {
        private Utils() {

        }

        public static byte[] BufferConcat(byte[] first, byte[] second)
        {
            byte[] combined = new byte[first.Length+second.Length];
            Buffer.BlockCopy(first, 0, combined, 0, first.Length);
            Buffer.BlockCopy(second, 0, combined, first.Length, second.Length);
            return combined;
        }
    }
}