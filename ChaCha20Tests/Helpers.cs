using System;

namespace ChaCha20Tests
{
    public static class Helpers
    {
        public static byte[] HexStringToBytes(string hex)
        {
            hex = hex.Replace(":", String.Empty).Replace(" ", String.Empty);

            int numberChars = hex.Length;
            byte[] bytes = new byte[numberChars / 2];
            for (int i = 0; i < numberChars; i += 2)
            {
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            }
            return bytes;
        }
    }
}
