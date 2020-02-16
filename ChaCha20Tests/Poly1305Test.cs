using ChaCha20;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;

namespace ChaCha20Tests
{
    [TestClass]
    public class Poly1305_ComputeTag
    {
        [TestMethod]
        public void CodeExample()
        {
            byte[] key = Helpers.HexStringToBytes("85:d6:be:78:57:55:6d:33:7f:44:52:fe:42:d5:06:a8:01:03:80:8a:fb:0d:b2:fd:4a:bf:f6:af:41:49:f5:1b");
            byte[] message = Helpers.HexStringToBytes(
                    "43 72 79 70 74 6f 67 72 61 70 68 69 63 20 46 6f" +
                    "72 75 6d 20 52 65 73 65 61 72 63 68 20 47 72 6f" +
                    "75 70"
               );
            byte[] expectedTag = Helpers.HexStringToBytes("a8:06:1d:c1:30:51:36:c6:c2:2b:8b:af:0c:01:27:a9");

            byte[] computedTag = Poly1305.ComputeTag(key, message);

            Console.WriteLine(BitConverter.ToString(expectedTag));
            Console.WriteLine(BitConverter.ToString(computedTag));
            CollectionAssert.AreEqual(expectedTag, computedTag);
        }

        [TestMethod]
        public void TestVector1()
        {
            byte[] key = Helpers.HexStringToBytes(
                    "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00" +
                    "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
                );
            byte[] message = Helpers.HexStringToBytes(
                    "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00" +
                    "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00" +
                    "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00" +
                    "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
               );
            byte[] expectedTag = Helpers.HexStringToBytes(
                    "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
                );

            byte[] computedTag = Poly1305.ComputeTag(key, message);

            Console.WriteLine(BitConverter.ToString(expectedTag));
            Console.WriteLine(BitConverter.ToString(computedTag));
            CollectionAssert.AreEqual(expectedTag, computedTag);
        }

        [TestMethod]
        public void TestVector2()
        {
            byte[] key = Helpers.HexStringToBytes(
                    "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00" +
                    "36 e5 f6 b5 c5 e0 60 70 f0 ef ca 96 22 7a 86 3e"
                );
            byte[] message = Helpers.HexStringToBytes(
                    "41 6e 79 20 73 75 62 6d 69 73 73 69 6f 6e 20 74" +
                    "6f 20 74 68 65 20 49 45 54 46 20 69 6e 74 65 6e" +
                    "64 65 64 20 62 79 20 74 68 65 20 43 6f 6e 74 72" +
                    "69 62 75 74 6f 72 20 66 6f 72 20 70 75 62 6c 69" +
                    "63 61 74 69 6f 6e 20 61 73 20 61 6c 6c 20 6f 72" +
                    "20 70 61 72 74 20 6f 66 20 61 6e 20 49 45 54 46" +
                    "20 49 6e 74 65 72 6e 65 74 2d 44 72 61 66 74 20" +
                    "6f 72 20 52 46 43 20 61 6e 64 20 61 6e 79 20 73" +
                    "74 61 74 65 6d 65 6e 74 20 6d 61 64 65 20 77 69" +
                    "74 68 69 6e 20 74 68 65 20 63 6f 6e 74 65 78 74" +
                    "20 6f 66 20 61 6e 20 49 45 54 46 20 61 63 74 69" +
                    "76 69 74 79 20 69 73 20 63 6f 6e 73 69 64 65 72" +
                    "65 64 20 61 6e 20 22 49 45 54 46 20 43 6f 6e 74" +
                    "72 69 62 75 74 69 6f 6e 22 2e 20 53 75 63 68 20" +
                    "73 74 61 74 65 6d 65 6e 74 73 20 69 6e 63 6c 75" +
                    "64 65 20 6f 72 61 6c 20 73 74 61 74 65 6d 65 6e" +
                    "74 73 20 69 6e 20 49 45 54 46 20 73 65 73 73 69" +
                    "6f 6e 73 2c 20 61 73 20 77 65 6c 6c 20 61 73 20" +
                    "77 72 69 74 74 65 6e 20 61 6e 64 20 65 6c 65 63" +
                    "74 72 6f 6e 69 63 20 63 6f 6d 6d 75 6e 69 63 61" +
                    "74 69 6f 6e 73 20 6d 61 64 65 20 61 74 20 61 6e" +
                    "79 20 74 69 6d 65 20 6f 72 20 70 6c 61 63 65 2c" +
                    "20 77 68 69 63 68 20 61 72 65 20 61 64 64 72 65" +
                    "73 73 65 64 20 74 6f                           "
               );
            byte[] expectedTag = Helpers.HexStringToBytes(
                    "36 e5 f6 b5 c5 e0 60 70 f0 ef ca 96 22 7a 86 3e"
                );

            byte[] computedTag = Poly1305.ComputeTag(key, message);

            Console.WriteLine(BitConverter.ToString(expectedTag));
            Console.WriteLine(BitConverter.ToString(computedTag));
            CollectionAssert.AreEqual(expectedTag, computedTag);
        }

        [TestMethod]
        public void TestVector3()
        {
            byte[] key = Helpers.HexStringToBytes(
                    "36 e5 f6 b5 c5 e0 60 70 f0 ef ca 96 22 7a 86 3e" +
                    "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
                );
            byte[] message = Helpers.HexStringToBytes(
                    "41 6e 79 20 73 75 62 6d 69 73 73 69 6f 6e 20 74" +
                    "6f 20 74 68 65 20 49 45 54 46 20 69 6e 74 65 6e" +
                    "64 65 64 20 62 79 20 74 68 65 20 43 6f 6e 74 72" +
                    "69 62 75 74 6f 72 20 66 6f 72 20 70 75 62 6c 69" +
                    "63 61 74 69 6f 6e 20 61 73 20 61 6c 6c 20 6f 72" +
                    "20 70 61 72 74 20 6f 66 20 61 6e 20 49 45 54 46" +
                    "20 49 6e 74 65 72 6e 65 74 2d 44 72 61 66 74 20" +
                    "6f 72 20 52 46 43 20 61 6e 64 20 61 6e 79 20 73" +
                    "74 61 74 65 6d 65 6e 74 20 6d 61 64 65 20 77 69" +
                    "74 68 69 6e 20 74 68 65 20 63 6f 6e 74 65 78 74" +
                    "20 6f 66 20 61 6e 20 49 45 54 46 20 61 63 74 69" +
                    "76 69 74 79 20 69 73 20 63 6f 6e 73 69 64 65 72" +
                    "65 64 20 61 6e 20 22 49 45 54 46 20 43 6f 6e 74" +
                    "72 69 62 75 74 69 6f 6e 22 2e 20 53 75 63 68 20" +
                    "73 74 61 74 65 6d 65 6e 74 73 20 69 6e 63 6c 75" +
                    "64 65 20 6f 72 61 6c 20 73 74 61 74 65 6d 65 6e" +
                    "74 73 20 69 6e 20 49 45 54 46 20 73 65 73 73 69" +
                    "6f 6e 73 2c 20 61 73 20 77 65 6c 6c 20 61 73 20" +
                    "77 72 69 74 74 65 6e 20 61 6e 64 20 65 6c 65 63" +
                    "74 72 6f 6e 69 63 20 63 6f 6d 6d 75 6e 69 63 61" +
                    "74 69 6f 6e 73 20 6d 61 64 65 20 61 74 20 61 6e" +
                    "79 20 74 69 6d 65 20 6f 72 20 70 6c 61 63 65 2c" +
                    "20 77 68 69 63 68 20 61 72 65 20 61 64 64 72 65" +
                    "73 73 65 64 20 74 6f                           "
               );
            byte[] expectedTag = Helpers.HexStringToBytes(
                    "f3 47 7e 7c d9 54 17 af 89 a6 b8 79 4c 31 0c f0"
                );

            byte[] computedTag = Poly1305.ComputeTag(key, message);

            Console.WriteLine(BitConverter.ToString(expectedTag));
            Console.WriteLine(BitConverter.ToString(computedTag));
            CollectionAssert.AreEqual(expectedTag, computedTag);
        }

        [TestMethod]
        public void TestVector4()
        {
            byte[] key = Helpers.HexStringToBytes(
                    "1c 92 40 a5 eb 55 d3 8a f3 33 88 86 04 f6 b5 f0" +
                    "47 39 17 c1 40 2b 80 09 9d ca 5c bc 20 70 75 c0"
                );
            byte[] message = Helpers.HexStringToBytes(
                    "27 54 77 61 73 20 62 72 69 6c 6c 69 67 2c 20 61" +
                    "6e 64 20 74 68 65 20 73 6c 69 74 68 79 20 74 6f" +
                    "76 65 73 0a 44 69 64 20 67 79 72 65 20 61 6e 64" +
                    "20 67 69 6d 62 6c 65 20 69 6e 20 74 68 65 20 77" +
                    "61 62 65 3a 0a 41 6c 6c 20 6d 69 6d 73 79 20 77" +
                    "65 72 65 20 74 68 65 20 62 6f 72 6f 67 6f 76 65" +
                    "73 2c 0a 41 6e 64 20 74 68 65 20 6d 6f 6d 65 20" +
                    "72 61 74 68 73 20 6f 75 74 67 72 61 62 65 2e   "
               );
            byte[] expectedTag = Helpers.HexStringToBytes(
                    "45 41 66 9a 7e aa ee 61 e7 08 dc 7c bc c5 eb 62"
                );

            byte[] computedTag = Poly1305.ComputeTag(key, message);

            Console.WriteLine(BitConverter.ToString(expectedTag));
            Console.WriteLine(BitConverter.ToString(computedTag));
            CollectionAssert.AreEqual(expectedTag, computedTag);
        }

        [TestMethod]
        public void TestVector5()
        {
            byte[] key = Helpers.HexStringToBytes(
                    "02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00" +
                    "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
                );
            byte[] message = Helpers.HexStringToBytes(
                    "FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF"
               );
            byte[] expectedTag = Helpers.HexStringToBytes(
                    "03 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
                );

            byte[] computedTag = Poly1305.ComputeTag(key, message);

            Console.WriteLine(BitConverter.ToString(expectedTag));
            Console.WriteLine(BitConverter.ToString(computedTag));
            CollectionAssert.AreEqual(expectedTag, computedTag);
        }

        [TestMethod]
        public void TestVector6()
        {
            byte[] key = Helpers.HexStringToBytes(
                    "02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00" +
                    "FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF"
                );
            byte[] message = Helpers.HexStringToBytes(
                    "02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
               );
            byte[] expectedTag = Helpers.HexStringToBytes(
                    "03 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
                );

            byte[] computedTag = Poly1305.ComputeTag(key, message);

            Console.WriteLine(BitConverter.ToString(expectedTag));
            Console.WriteLine(BitConverter.ToString(computedTag));
            CollectionAssert.AreEqual(expectedTag, computedTag);
        }

        [TestMethod]
        public void TestVector7()
        {
            byte[] key = Helpers.HexStringToBytes(
                    "01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00" +
                    "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
                );
            byte[] message = Helpers.HexStringToBytes(
                    "FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF" +
                    "F0 FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF" +
                    "11 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
               );
            byte[] expectedTag = Helpers.HexStringToBytes(
                    "05 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
                );

            byte[] computedTag = Poly1305.ComputeTag(key, message);

            Console.WriteLine(BitConverter.ToString(expectedTag));
            Console.WriteLine(BitConverter.ToString(computedTag));
            CollectionAssert.AreEqual(expectedTag, computedTag);
        }

        [TestMethod]
        public void TestVector8()
        {
            byte[] key = Helpers.HexStringToBytes(
                    "01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00" +
                    "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
                );
            byte[] message = Helpers.HexStringToBytes(
                    "FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF" +
                    "FB FE FE FE FE FE FE FE FE FE FE FE FE FE FE FE" +
                    "01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01"
               );
            byte[] expectedTag = Helpers.HexStringToBytes(
                    "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
                );

            byte[] computedTag = Poly1305.ComputeTag(key, message);

            Console.WriteLine(BitConverter.ToString(expectedTag));
            Console.WriteLine(BitConverter.ToString(computedTag));
            CollectionAssert.AreEqual(expectedTag, computedTag);
        }

        [TestMethod]
        public void TestVector9()
        {
            byte[] key = Helpers.HexStringToBytes(
                    "02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00" +
                    "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
                );
            byte[] message = Helpers.HexStringToBytes(
                    "FD FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF"
               );
            byte[] expectedTag = Helpers.HexStringToBytes(
                    "FA FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF"
                );

            byte[] computedTag = Poly1305.ComputeTag(key, message);

            Console.WriteLine(BitConverter.ToString(expectedTag));
            Console.WriteLine(BitConverter.ToString(computedTag));
            CollectionAssert.AreEqual(expectedTag, computedTag);
        }

        [TestMethod]
        public void TestVector10()
        {
            byte[] key = Helpers.HexStringToBytes(
                    "01 00 00 00 00 00 00 00 04 00 00 00 00 00 00 00" +
                    "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
                );
            byte[] message = Helpers.HexStringToBytes(
                    "E3 35 94 D7 50 5E 43 B9 00 00 00 00 00 00 00 00" +
                    "33 94 D7 50 5E 43 79 CD 01 00 00 00 00 00 00 00" +
                    "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00" +
                    "01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
               );
            byte[] expectedTag = Helpers.HexStringToBytes(
                    "14 00 00 00 00 00 00 00 55 00 00 00 00 00 00 00"
                );

            byte[] computedTag = Poly1305.ComputeTag(key, message);

            Console.WriteLine(BitConverter.ToString(expectedTag));
            Console.WriteLine(BitConverter.ToString(computedTag));
            CollectionAssert.AreEqual(expectedTag, computedTag);
        }

        [TestMethod]
        public void TestVector11()
        {
            byte[] key = Helpers.HexStringToBytes(
                    "01 00 00 00 00 00 00 00 04 00 00 00 00 00 00 00" +
                    "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
                );
            byte[] message = Helpers.HexStringToBytes(
                    "E3 35 94 D7 50 5E 43 B9 00 00 00 00 00 00 00 00" +
                    "33 94 D7 50 5E 43 79 CD 01 00 00 00 00 00 00 00" +
                    "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
               );
            byte[] expectedTag = Helpers.HexStringToBytes(
                    "13 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
                );

            byte[] computedTag = Poly1305.ComputeTag(key, message);

            Console.WriteLine(BitConverter.ToString(expectedTag));
            Console.WriteLine(BitConverter.ToString(computedTag));
            CollectionAssert.AreEqual(expectedTag, computedTag);
        }
    }

    [TestClass]
    public class Poly1305_DeriveKey
    {
        [TestMethod]
        public void CodeExample()
        {
            uint[] masterKey = BitHelpers.LittleEndianBytesToIntegers(
                Helpers.HexStringToBytes(
                    "80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f" +
                    "90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f"
                ));
            uint[] nonce = BitHelpers.LittleEndianBytesToIntegers(
                Helpers.HexStringToBytes("00 00 00 00 00 01 02 03 04 05 06 07"));
            byte[] expectedKey = Helpers.HexStringToBytes(
                    "8a d5 a0 8b 90 5f 81 cc 81 50 40 27 4a b2 94 71" +
                    "a8 33 b6 37 e3 fd 0d a5 08 db b8 e2 fd d1 a6 46"
               );

            byte[] computedKey = Poly1305.DeriveKey(masterKey, nonce);

            Console.WriteLine(BitConverter.ToString(expectedKey));
            Console.WriteLine(BitConverter.ToString(computedKey));
            CollectionAssert.AreEqual(expectedKey, computedKey);
        }

        [TestMethod]
        public void TestVector1()
        {
            uint[] masterKey = BitHelpers.LittleEndianBytesToIntegers(
                Helpers.HexStringToBytes(
                    "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00" +
                    "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
                ));
            uint[] nonce = BitHelpers.LittleEndianBytesToIntegers(
                Helpers.HexStringToBytes(
                    "00 00 00 00 00 00 00 00 00 00 00 00            "
                ));
            byte[] expectedKey = Helpers.HexStringToBytes(
                    "76 b8 e0 ad a0 f1 3d 90 40 5d 6a e5 53 86 bd 28" +
                    "bd d2 19 b8 a0 8d ed 1a a8 36 ef cc 8b 77 0d c7"
               );

            byte[] computedKey = Poly1305.DeriveKey(masterKey, nonce);

            Console.WriteLine(BitConverter.ToString(expectedKey));
            Console.WriteLine(BitConverter.ToString(computedKey));
            CollectionAssert.AreEqual(expectedKey, computedKey);
        }

        [TestMethod]
        public void TestVector2()
        {
            uint[] masterKey = BitHelpers.LittleEndianBytesToIntegers(
                Helpers.HexStringToBytes(
                    "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00" +
                    "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01"
                ));
            uint[] nonce = BitHelpers.LittleEndianBytesToIntegers(
                Helpers.HexStringToBytes(
                    "00 00 00 00 00 00 00 00 00 00 00 02            "
                ));
            byte[] expectedKey = Helpers.HexStringToBytes(
                    "ec fa 25 4f 84 5f 64 74 73 d3 cb 14 0d a9 e8 76" +
                    "06 cb 33 06 6c 44 7b 87 bc 26 66 dd e3 fb b7 39"
               );

            byte[] computedKey = Poly1305.DeriveKey(masterKey, nonce);

            Console.WriteLine(BitConverter.ToString(expectedKey));
            Console.WriteLine(BitConverter.ToString(computedKey));
            CollectionAssert.AreEqual(expectedKey, computedKey);
        }

        [TestMethod]
        public void TestVector3()
        {
            uint[] masterKey = BitHelpers.LittleEndianBytesToIntegers(
                Helpers.HexStringToBytes(
                    "1c 92 40 a5 eb 55 d3 8a f3 33 88 86 04 f6 b5 f0" +
                    "47 39 17 c1 40 2b 80 09 9d ca 5c bc 20 70 75 c0"
                ));
            uint[] nonce = BitHelpers.LittleEndianBytesToIntegers(
                Helpers.HexStringToBytes(
                    "00 00 00 00 00 00 00 00 00 00 00 02            "
                ));
            byte[] expectedKey = Helpers.HexStringToBytes(
                    "96 5e 3b c6 f9 ec 7e d9 56 08 08 f4 d2 29 f9 4b" +
                    "13 7f f2 75 ca 9b 3f cb dd 59 de aa d2 33 10 ae"
               );

            byte[] computedKey = Poly1305.DeriveKey(masterKey, nonce);

            Console.WriteLine(BitConverter.ToString(expectedKey));
            Console.WriteLine(BitConverter.ToString(computedKey));
            CollectionAssert.AreEqual(expectedKey, computedKey);
        }
    }
}
