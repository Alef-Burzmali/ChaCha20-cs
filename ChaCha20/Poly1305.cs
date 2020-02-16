using System;
using System.Numerics;
using System.Runtime.CompilerServices;

[assembly: InternalsVisibleTo("ChaCha20Tests")]
namespace ChaCha20
{
    internal class Poly1305
    {
        public const int KeyLength = 32;
        protected const int BlockLength = 16;
        public const int TagLength = 16;

        public static readonly BigInteger Clamp = BigInteger.Parse("0ffffffc0ffffffc0ffffffc0fffffff", System.Globalization.NumberStyles.HexNumber);
        public static readonly BigInteger P = BigInteger.Parse("3fffffffffffffffffffffffffffffffb", System.Globalization.NumberStyles.HexNumber);
        public static readonly BigInteger BitMask = BigInteger.Parse("0ffffffffffffffffffffffffffffffff", System.Globalization.NumberStyles.HexNumber);

        public static byte[] ComputeTag(byte[] key, byte[] message)
        {
            byte[] rBytes = new byte[16];
            byte[] sBytes = new byte[16];
            Array.Copy(key, 0, rBytes, 0, 16);
            Array.Copy(key, 16, sBytes, 0, 16);

            BigInteger r = new BigInteger(rBytes);
            BigInteger s = new BigInteger(sBytes);

            r &= Clamp;

            BigInteger accumulator = new BigInteger(0);

            uint numberOfFullBlocks = (uint)Math.Floor((float)message.Length / BlockLength);
            for (uint block = 0; block < numberOfFullBlocks; block++)
            {
                byte[] messageChunk = new byte[BlockLength + 1];
                Array.Copy(message, BlockLength * block, messageChunk, 0, BlockLength);
                messageChunk[BlockLength] = 1;
                accumulator = (accumulator + new BigInteger(messageChunk)) % P;
                accumulator = (accumulator * r) % P;
            }
            if (message.Length % BlockLength > 0)
            {
                byte[] messageChunk = new byte[message.Length % BlockLength + 1];
                Array.Copy(message, BlockLength * numberOfFullBlocks, messageChunk, 0, message.Length % BlockLength);
                messageChunk[message.Length % BlockLength] = 1;
                accumulator = (accumulator + new BigInteger(messageChunk)) % P;
                accumulator = (accumulator * r) % P;
            }

            accumulator = (accumulator + s) & BitMask;

            byte[] byteArray = accumulator.ToByteArray();
            byte[] output = new byte[BlockLength];
            Array.Copy(byteArray, 0, output, 0, Math.Min(byteArray.Length, BlockLength));
            return output;
        }
        
        public static byte[] DeriveKey(uint[] masterKey, uint[] nonce)
        {
            byte[] keyByte = new byte[KeyLength];
            Array.Copy(ChaCha20Block.GetKeystreamBlock(masterKey, nonce, 0), keyByte, KeyLength);
            return keyByte;
        }
    }
}
