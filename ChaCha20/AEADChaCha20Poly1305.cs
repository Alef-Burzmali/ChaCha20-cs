using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;

[assembly: InternalsVisibleTo("ChaCha20Tests")]
namespace ChaCha20
{
    public class DecryptErrorException : Exception
    {
    }

    public class AEADChaCha20Poly1305
    {
        internal static byte[] ComputeTag(byte[] poly1305Key, byte[] ciphertext, byte[] aad)
        {
            byte[] aadPadding = BitHelpers.Pad16Bytes((int)aad.LongLength);
            byte[] ciphertextPadding = BitHelpers.Pad16Bytes((int)ciphertext.LongLength);

            byte[] aadLengthAsByte = BitHelpers.LongToLittleEndianBytes(new ulong[] { (ulong)aad.LongLength });
            byte[] ciphertextLengthAsByte = BitHelpers.LongToLittleEndianBytes(new ulong[] { (ulong)ciphertext.LongLength });

            byte[] authenticatedMessage = new byte[
                    aad.Length +
                    aadPadding.Length +
                    ciphertext.Length +
                    ciphertextPadding.Length +
                    8 + 8 // lengths of AAD and ciphertext
                ];

            long position = 0;
            aad.CopyTo(authenticatedMessage, position);
            position += aad.LongLength;
            aadPadding.CopyTo(authenticatedMessage, position);
            position += aadPadding.LongLength;
            ciphertext.CopyTo(authenticatedMessage, position);
            position += ciphertext.LongLength;
            ciphertextPadding.CopyTo(authenticatedMessage, position);
            position += ciphertextPadding.LongLength;
            aadLengthAsByte.CopyTo(authenticatedMessage, position);
            position += aadLengthAsByte.LongLength;
            ciphertextLengthAsByte.CopyTo(authenticatedMessage, position);
            
            byte[] tag = Poly1305.ComputeTag(poly1305Key, authenticatedMessage);
            return tag;
        }

        public static byte[] Encrypt(uint[] key, uint[] nonce, byte[] plaintext, byte[] additionalAuthenticatedData)
        {
            byte[] poly1305Key = Poly1305.DeriveKey(key, nonce);
            byte[] ciphertext = ChaCha20Cipher.Encrypt(key, nonce, 1, plaintext);
            byte[] tag = ComputeTag(poly1305Key, ciphertext, additionalAuthenticatedData);

            byte[] output = new byte[ciphertext.LongLength + tag.Length];
            ciphertext.CopyTo(output, 0);
            tag.CopyTo(output, ciphertext.LongLength);
            return output;
        }

        public static byte[] Encrypt(uint[] key, uint[] nonce, byte[] plaintext)
        {
            byte[] aad = {};
            return Encrypt(key, nonce, plaintext, aad);
        }

        public static byte[] Decrypt(uint[] key, uint[] nonce, byte[] ciphertext, byte[] additionalAuthenticatedData)
        {
            Debug.Assert(ciphertext.Length >= Poly1305.TagLength);

            byte[] providedTag = new byte[Poly1305.TagLength];
            byte[] ciphertextWithoutTag = new byte[ciphertext.LongLength - Poly1305.TagLength];
            Array.Copy(ciphertext, 0, ciphertextWithoutTag, 0, ciphertextWithoutTag.LongLength);
            Array.Copy(ciphertext, ciphertextWithoutTag.LongLength, providedTag, 0, Poly1305.TagLength);

            byte[] poly1305Key = Poly1305.DeriveKey(key, nonce);
            byte[] plaintext = ChaCha20Cipher.Encrypt(key, nonce, 1, ciphertextWithoutTag);
            byte[] computedtag = ComputeTag(poly1305Key, ciphertextWithoutTag, additionalAuthenticatedData);

            if (BitHelpers.BytesAreEqualConstantTime(computedtag, providedTag))
            {
                return plaintext;
            }
            else
            {
                throw new DecryptErrorException();
            }
        }

        public static byte[] Decrypt(uint[] key, uint[] nonce, byte[] ciphertext)
        {
            byte[] aad = { };
            return Decrypt(key, nonce, ciphertext, aad);
        }
    }
}
