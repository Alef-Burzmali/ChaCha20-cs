using ChaCha20;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace ChaCha20Tests
{
    [TestClass]
    public class BitHelpers_RotateLeft
    {
        [TestMethod]
        public void PowersOfTwo()
        {
            for (int shift = 0; shift < 32; shift++)
            {
                uint expected = (uint)1 << shift;

                uint computed = BitHelpers.RotateLeft(1, shift);

                Assert.AreEqual(expected, computed);
            }
        }

        [TestMethod]
        public void RotateBy32()
        {
            uint[] tests = { 0, 1, 5, 147, 12 };
            foreach (uint n in tests)
            {
                uint expected = n;

                uint computed = BitHelpers.RotateLeft(n, 32);

                Assert.AreEqual(expected, computed);
            }
        }

        [TestMethod]
        public void SpecialValues()
        {
            uint[] inputs = { 3, 12, uint.MaxValue };
            int[] shifts = { 1, 5, 12 };
            uint[] expectedResults = { 6, 384, uint.MaxValue };

            for (int i = 0; i < inputs.Length; i++)
            {
                uint expected = expectedResults[i];

                uint computed = BitHelpers.RotateLeft(inputs[i], shifts[i]);

                Assert.AreEqual(expected, computed);
            }
        }
    }

    [TestClass]
    public class BitHelpers_IntToLittleEndianBytes
    {
        [TestMethod]
        public void SpecialValues()
        {
            uint[] inputs = { 0, 3, 256 + 12, 0x32547698, uint.MaxValue, uint.MaxValue - 1 };
            byte[,] expectedResults = {
                { 0x00, 0x00, 0x00, 0x00 },
                { 0x03, 0x00, 0x00, 0x00 },
                { 0x0c, 0x01, 0x00, 0x00 },
                { 0x98, 0x76, 0x54, 0x32 },
                { 0xff, 0xff, 0xff, 0xff },
                { 0xfe, 0xff, 0xff, 0xff },
            };

            for (int i = 0; i < inputs.Length; i++)
            {
                uint[] input = { inputs[i] };
                byte[] expected = new byte[4];
                for (int j = 0; j < expected.Length; j++)
                {
                    expected[j] = expectedResults[i, j];
                }

                byte[] computed = BitHelpers.IntToLittleEndianBytes(input);

                CollectionAssert.AreEqual(expected, computed);
            }
        }

        [TestMethod]
        public void OneArrayOfInt()
        {
            uint[] input = { 0, 3, 256 + 12, 0x32547698, uint.MaxValue, uint.MaxValue - 1 };
            byte[] expected = {
                0x00, 0x00, 0x00, 0x00,
                0x03, 0x00, 0x00, 0x00,
                0x0c, 0x01, 0x00, 0x00,
                0x98, 0x76, 0x54, 0x32,
                0xff, 0xff, 0xff, 0xff,
                0xfe, 0xff, 0xff, 0xff,
            };

            byte[] computed = BitHelpers.IntToLittleEndianBytes(input);

            CollectionAssert.AreEqual(expected, computed);
        }
    }

    [TestClass]
    public class BitHelpers_LongToLittleEndianBytes
    {
        [TestMethod]
        public void SpecialValues()
        {
            ulong[] inputs = { 0, 3, 256 + 12, 0xbadcfe1032547698, ulong.MaxValue, ulong.MaxValue - 1 };
            byte[,] expectedResults = {
                { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
                { 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
                { 0x0c, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
                { 0x98, 0x76, 0x54, 0x32, 0x10, 0xfe, 0xdc, 0xba },
                { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
                { 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
            };

            for (int i = 0; i < inputs.Length; i++)
            {
                ulong[] input = { inputs[i] };
                byte[] expected = new byte[8];
                for (int j = 0; j < expected.Length; j++)
                {
                    expected[j] = expectedResults[i, j];
                }

                byte[] computed = BitHelpers.LongToLittleEndianBytes(input);

                CollectionAssert.AreEqual(expected, computed);
            }
        }

        [TestMethod]
        public void OneArrayOfInt()
        {
            ulong[] input = { 0, 3, 256 + 12, 0xbadcfe1032547698, ulong.MaxValue, ulong.MaxValue - 1 };
            byte[] expected = {
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x0c, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x98, 0x76, 0x54, 0x32, 0x10, 0xfe, 0xdc, 0xba,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            };

            byte[] computed = BitHelpers.LongToLittleEndianBytes(input);

            CollectionAssert.AreEqual(expected, computed);
        }
    }

    [TestClass]
    public class BitHelpers_LittleEndianBytesToIntegers
    {
        [TestMethod]
        public void SpecialValues()
        {
            uint[] expectedResults = { 0, 3, 256 + 12, 0x32547698, uint.MaxValue, uint.MaxValue - 1 };
            byte[,] inputs = {
                { 0x00, 0x00, 0x00, 0x00 },
                { 0x03, 0x00, 0x00, 0x00 },
                { 0x0c, 0x01, 0x00, 0x00 },
                { 0x98, 0x76, 0x54, 0x32 },
                { 0xff, 0xff, 0xff, 0xff },
                { 0xfe, 0xff, 0xff, 0xff },
            };

            for (int i = 0; i < expectedResults.Length; i++)
            {
                uint[] expected = { expectedResults[i] };
                byte[] input = new byte[4];
                for (int j = 0; j < 4; j++)
                {
                    input[j] = inputs[i, j];
                }

                uint[] computed = BitHelpers.LittleEndianBytesToIntegers(input);

                CollectionAssert.AreEqual(expected, computed);
            }
        }

        [TestMethod]
        public void OneArrayOfInt()
        {
            uint[] expected = { 0, 3, 256 + 12, 0x32547698, uint.MaxValue, uint.MaxValue - 1 };
            byte[] input = {
                0x00, 0x00, 0x00, 0x00,
                0x03, 0x00, 0x00, 0x00,
                0x0c, 0x01, 0x00, 0x00,
                0x98, 0x76, 0x54, 0x32,
                0xff, 0xff, 0xff, 0xff,
                0xfe, 0xff, 0xff, 0xff,
            };

            uint[] computed = BitHelpers.LittleEndianBytesToIntegers(input);

            CollectionAssert.AreEqual(expected, computed);
        }
    }

    [TestClass]
    public class BitHelpers_ByteArrayXor
    {
        [TestMethod]
        public void XorLeftThenRightWithSameNumberOfBytes()
        {
            byte[] left = {
                  0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x0c, 0x01, 0x00, 0x00, 0x98, 0x76, 0x54, 0x32, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff
            };
            byte[,] rightValues = {
                { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
                { 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x0c, 0x01, 0x00, 0x00, 0x98, 0x76, 0x54, 0x32, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff },
                { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
                { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef },
            };
            byte[,] expectedResults = {
                { 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x0c, 0x01, 0x00, 0x00, 0x98, 0x76, 0x54, 0x32, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff },
                { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
                { 0xff, 0xff, 0xff, 0xff, 0xfc, 0xff, 0xff, 0xff, 0xf3, 0xfe, 0xff, 0xff, 0x67, 0x89, 0xab, 0xcd, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00 },
                { 0x01, 0x23, 0x45, 0x67, 0x8a, 0xab, 0xcd, 0xef, 0x0d, 0x22, 0x45, 0x67, 0x11, 0xdd, 0x99, 0xdd, 0xfe, 0xdc, 0xba, 0x98, 0x77, 0x54, 0x32, 0x10 },
            };

            for (int i = 0; i < rightValues.Length / left.Length; i++)
            {
                byte[] right = new byte[left.Length];
                byte[] expected = new byte[left.Length];
                for (int j = 0; j < left.Length; j++)
                {
                    right[j] = rightValues[i, j];
                    expected[j] = expectedResults[i, j];
                }

                byte[] computedLeftRight = BitHelpers.ByteArrayXor(left, right);
                byte[] computedRightLeft = BitHelpers.ByteArrayXor(right, left);

                CollectionAssert.AreEqual(expected, computedLeftRight);
                CollectionAssert.AreEqual(expected, computedRightLeft);
            }
        }

        [TestMethod]
        public void UnbalancedNumberOfBytes()
        {
            byte[] left = { 0x00, 0x00, 0x00, 0x00, 0x03 };
            byte[] right = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd };
            byte[] expected = { 0x01, 0x23, 0x45, 0x67, 0x8a };

            byte[] computedLeftRight = BitHelpers.ByteArrayXor(left, right);
            byte[] computedRightLeft = BitHelpers.ByteArrayXor(right, left);

            CollectionAssert.AreEqual(expected, computedLeftRight);
            CollectionAssert.AreEqual(expected, computedRightLeft);
        }

        [TestMethod]
        public void EmptyInput()
        {
            byte[] left = { 0x00, 0x00, 0x00, 0x00, 0x03 };
            byte[] right = {};
            byte[] expected = {};

            byte[] computedLeftRight = BitHelpers.ByteArrayXor(left, right);
            byte[] computedRightLeft = BitHelpers.ByteArrayXor(right, left);

            CollectionAssert.AreEqual(expected, computedLeftRight);
            CollectionAssert.AreEqual(expected, computedRightLeft);
        }
    }

    [TestClass]
    public class BitHelpers_Pad16Bytes
    {
        [TestMethod]
        public void AllZero()
        {
            for (int i = 0; i < 32; i++)
            {
                byte[] padding = BitHelpers.Pad16Bytes(i);

                foreach (byte b in padding)
                {
                    Assert.AreEqual(0, b);
                }
            }
        }

        [TestMethod]
        public void AlignedTo16Bytes()
        {
            for (int i = 0; i < 255; i++)
            {
                byte[] padding = BitHelpers.Pad16Bytes(i);

                int totalLength = i + padding.Length;
                bool isMultipleOf16 = (totalLength % 16) == 0;

                Assert.IsTrue(isMultipleOf16);
            }
        }

        [TestMethod]
        public void AlwaysBetween0And16Bytes()
        {
            for (int i = 0; i < 255; i++)
            {
                byte[] padding = BitHelpers.Pad16Bytes(i);

                bool isBetween0And16 = (padding.Length >= 0) && (padding.Length < 16);

                Assert.IsTrue(isBetween0And16);
            }
        }

        [TestMethod]
        public void UnbalancedNumberOfBytes()
        {
            byte[] left = { 0x00, 0x00, 0x00, 0x00, 0x03 };
            byte[] right = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd };
            byte[] expected = { 0x01, 0x23, 0x45, 0x67, 0x8a };

            byte[] computedLeftRight = BitHelpers.ByteArrayXor(left, right);
            byte[] computedRightLeft = BitHelpers.ByteArrayXor(right, left);

            CollectionAssert.AreEqual(expected, computedLeftRight);
            CollectionAssert.AreEqual(expected, computedRightLeft);
        }

        [TestMethod]
        public void EmptyInput()
        {
            byte[] left = { 0x00, 0x00, 0x00, 0x00, 0x03 };
            byte[] right = { };
            byte[] expected = { };

            byte[] computedLeftRight = BitHelpers.ByteArrayXor(left, right);
            byte[] computedRightLeft = BitHelpers.ByteArrayXor(right, left);

            CollectionAssert.AreEqual(expected, computedLeftRight);
            CollectionAssert.AreEqual(expected, computedRightLeft);
        }
    }

    [TestClass]
    public class BitHelpers_BytesAreEqualConstantTime
    {
        [TestMethod]
        public void SameArraysAreEquals()
        {
            byte[,] values = {
                { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
                { 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x0c, 0x01, 0x00, 0x00, 0x98, 0x76, 0x54, 0x32, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff },
                { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
                { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef },
            };

            for (int i = 0; i < 4; i++)
            {
                byte[] left = new byte[values.Length / 4];
                byte[] right = new byte[values.Length / 4];
                for (int j = 0; j < values.Length / 4; j++)
                {
                    left[j] = values[i, j];
                    right[j] = values[i, j];
                }

                bool result = BitHelpers.BytesAreEqualConstantTime(left, right);

                Assert.IsTrue(result);
            }
        }

        [TestMethod]
        public void OffByOneAreDifferent()
        {
            byte[,] values = {
                { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
                { 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x0c, 0x01, 0x00, 0x00, 0x98, 0x76, 0x54, 0x32, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff },
                { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
                { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef },
            };

            for (int i = 0; i < 4; i++)
            {
                byte[] left = new byte[values.Length / 4];
                byte[] right = new byte[values.Length / 4 - 1];
                for (int j = 0; j < values.Length / 4; j++)
                {
                    left[j] = values[i, j];
                    if (j < values.Length / 4 - 1)
                    {
                        right[j] = values[i, j];
                    }
                }

                bool resultLeftRight = BitHelpers.BytesAreEqualConstantTime(left, right);
                bool resultRightLeft = BitHelpers.BytesAreEqualConstantTime(right, left);

                Assert.IsFalse(resultLeftRight);
                Assert.IsFalse(resultRightLeft);
            }
        }

        [TestMethod]
        public void DifferentArraysAreDifferent()
        {
            byte[,] values = {
                { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
                { 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x0c, 0x01, 0x00, 0x00, 0x98, 0x76, 0x54, 0x32, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff },
                { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
                { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef },
            };

            for (int i = 0; i < 8; i++)
            {
                byte[] left = new byte[values.Length / 4];
                byte[] right = new byte[values.Length / 4];
                for (int j = 0; j < values.Length / 4; j++)
                {
                    left[j] = values[i % 4, j];
                    right[j] = values[(i + 1) % 4, j];
                }

                bool resultLeftRight = BitHelpers.BytesAreEqualConstantTime(left, right);
                bool resultRightLeft = BitHelpers.BytesAreEqualConstantTime(right, left);

                Assert.IsFalse(resultLeftRight);
                Assert.IsFalse(resultRightLeft);
            }
        }

        [TestMethod]
        public void DifferentArraysWithDifferentLengthAreDifferent()
        {
            byte[] left = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
            byte[] right = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x11, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef };

            bool resultLeftRight = BitHelpers.BytesAreEqualConstantTime(left, right);
            bool resultRightLeft = BitHelpers.BytesAreEqualConstantTime(right, left);

            Assert.IsFalse(resultLeftRight);
            Assert.IsFalse(resultRightLeft);
        }

        [TestMethod]
        public void OneBitDifferentAreDifferent()
        {
            byte[] left = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef };
            byte[] right = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x11, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef };

            bool resultLeftRight = BitHelpers.BytesAreEqualConstantTime(left, right);
            bool resultRightLeft = BitHelpers.BytesAreEqualConstantTime(right, left);

            Assert.IsFalse(resultLeftRight);
            Assert.IsFalse(resultRightLeft);
        }

        [TestMethod]
        public void ShiftedArraysAreDifferent()
        {
            byte[] left = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef };
            byte[] right = { 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd };

            bool resultLeftRight = BitHelpers.BytesAreEqualConstantTime(left, right);
            bool resultRightLeft = BitHelpers.BytesAreEqualConstantTime(right, left);

            Assert.IsFalse(resultLeftRight);
            Assert.IsFalse(resultRightLeft);
        }
    }
}
