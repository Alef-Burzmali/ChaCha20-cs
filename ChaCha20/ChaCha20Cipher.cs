using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;

[assembly: InternalsVisibleTo("ChaCha20Tests")]
namespace ChaCha20
{
    internal class ChaCha20Block
    {
        public const int BlockLength = 64;
        protected readonly uint[] InitializationConstants = { 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574 };

        protected uint[] State;

        protected ChaCha20Block(ChaCha20Block copy)
        {
            this.State = new uint[16];
            copy.State.CopyTo(this.State, 0);
        }

        public ChaCha20Block(uint[] key, uint[] nonce, uint blockCount = 0)
        {
            this.State = new uint[16];
            Debug.Assert(key.Length == 8, "Key must be a 8-long uint array");
            Debug.Assert(nonce.Length == 3, "Nonce must be a 3-long uint array");

            InitializationConstants.CopyTo(this.State, 0);
            key.CopyTo(this.State, 4);
            this.State[12] = blockCount;
            nonce.CopyTo(this.State, 13);
        }

        protected void SetBlockCount(uint blockCount)
        {
            this.State[12] = blockCount;
        }

        protected void QuarterRound(int a, int b, int c, int d)
        {
            // uint provides free modulo 32b
            State[a] += State[b]; State[d] = BitHelpers.RotateLeft(State[a] ^ State[d], 16);
            State[c] += State[d]; State[b] = BitHelpers.RotateLeft(State[b] ^ State[c], 12);
            State[a] += State[b]; State[d] = BitHelpers.RotateLeft(State[a] ^ State[d], 8);
            State[c] += State[d]; State[b] = BitHelpers.RotateLeft(State[b] ^ State[c], 7);
        }

        protected void RunBlock(ChaCha20Block initialState)
        {
            for (int i = 0; i < 10; i++)
            {
                QuarterRound(0, 4, 8, 12);
                QuarterRound(1, 5, 9, 13);
                QuarterRound(2, 6, 10, 14);
                QuarterRound(3, 7, 11, 15);

                QuarterRound(0, 5, 10, 15);
                QuarterRound(1, 6, 11, 12);
                QuarterRound(2, 7, 8, 13);
                QuarterRound(3, 4, 9, 14);
            }

            for (int i = 0; i < 16; i++)
            {
                this.State[i] += initialState.State[i];
            }
        }

        protected byte[] Serialize()
        {
            return BitHelpers.IntToLittleEndianBytes(State);
        }

        public static byte[] GetKeystreamBlock(uint[] key, uint[] nonce, uint blockCount = 0)
        {
            var initialState = new ChaCha20Block(key, nonce, blockCount);
            var workingState = new ChaCha20Block(initialState);
            workingState.RunBlock(initialState);
            return workingState.Serialize();
        }

        public static byte[] GetKeystreamBlock(ChaCha20Block initialState, uint blockCount)
        {
            initialState.SetBlockCount(blockCount);
            var workingState = new ChaCha20Block(initialState);
            workingState.RunBlock(initialState);
            return workingState.Serialize();
        }
    }
    internal class ChaCha20Cipher
    {
        public static byte[] Encrypt(uint[] key, uint[] nonce, uint initialBlockCount, byte[] message)
        {
            Debug.Assert(key.Length == 8, "Key must be a 8-long uint array");
            Debug.Assert(nonce.Length == 3, "Nonce must be a 3-long uint array");

            var initialState = new ChaCha20Block(key, nonce, initialBlockCount);

            byte[] ciphertext = new byte[message.Length];
            uint numberOfFullBlocks = (uint)Math.Floor((float)message.Length / ChaCha20Block.BlockLength);
            for (uint block = 0; block < numberOfFullBlocks; block++)
            {
                byte[] keystream = ChaCha20Block.GetKeystreamBlock(initialState, initialBlockCount + block);
                byte[] messageChunk = new byte[ChaCha20Block.BlockLength];

                Array.Copy(message, ChaCha20Block.BlockLength * block, messageChunk, 0, ChaCha20Block.BlockLength);

                byte[] ciphertextChunk = BitHelpers.ByteArrayXor(keystream, messageChunk);
                ciphertextChunk.CopyTo(ciphertext, ChaCha20Block.BlockLength * block);
            }
            if (message.Length % ChaCha20Block.BlockLength > 0)
            {
                byte[] keystream = ChaCha20Block.GetKeystreamBlock(initialState, initialBlockCount + numberOfFullBlocks);
                byte[] messageChunk = new byte[message.Length % ChaCha20Block.BlockLength];

                Array.Copy(message, ChaCha20Block.BlockLength * numberOfFullBlocks, messageChunk, 0, message.Length % ChaCha20Block.BlockLength);

                byte[] ciphertextChunk = BitHelpers.ByteArrayXor(keystream, messageChunk);
                ciphertextChunk.CopyTo(ciphertext, ChaCha20Block.BlockLength * numberOfFullBlocks);
            }

            return ciphertext;
        }
    }
}
