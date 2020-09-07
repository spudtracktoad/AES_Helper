using AESEncryption;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AES_Tests
{
    [TestClass]
    public class CipherTests
    {
        AES aesTest;
        byte[,] TestState;
        byte[,] TestStateResult;

        [TestInitialize]
        public void setup()
        {
            aesTest = new AES(Constants.EncryptionMode.AES128);
        }

        [TestMethod]
        public void mixColumnsTest()
        {
            TestState = new byte[,] {{ 0xd4, 0xbf, 0x5d, 0x30},
                                     { 0xe0, 0xb4, 0x52, 0xae},
                                     { 0xb8, 0x41, 0x11, 0xf1},
                                     { 0x1e, 0x27, 0x98, 0xe5}};

            TestStateResult = new byte[,] {{ 0x04, 0x66, 0x81, 0xe5},
                                           { 0xe0, 0xcb, 0x19, 0x9a},
                                           { 0x48, 0xf8, 0xd3, 0x7a},
                                           { 0x28, 0x06, 0x26, 0x4c}};

            aesTest.state = TestState;

            aesTest.mixColumns();

            var result = aesTest.state;

            for (int i = 0; i < 4; i++)
            {
                for (int d = 0; d < 4; d++)
                {
                    Assert.IsTrue(result[i, d] == TestStateResult[i, d]);
                }
            }
        }

        [TestMethod]
        public void subWordTest()
        {

            TestState = new byte[,] {{ 0x19, 0xa0, 0x9a, 0xe9 },
                                         { 0x3d, 0xf4, 0xc6, 0xf8 },
                                         { 0xe3, 0xe2, 0x8d, 0x48 },
                                         { 0xbe, 0x2b, 0x2a, 0x08 } };

            TestStateResult = new byte[,] {{ 0xd4, 0xe0, 0xb8, 0x1e },
                                               { 0x27, 0xbf, 0xb4, 0x41 },
                                               { 0x11, 0x98, 0x5d, 0x52 },
                                               { 0xae, 0xf1, 0xe5, 0x30 } };
            aesTest.state = TestState;

            aesTest.subBytes();

            var result = aesTest.state;

            for (int i = 0; i < 4; i++)
            {
                for (int d = 0; d < 4; d++)
                {
                    Assert.IsTrue(result[i, d] == TestStateResult[i, d]);
                }
            }
        }

        [TestMethod]
        public void shiftRowTest()
        {

            TestState = new byte[,] {{ 0xd4, 0x27, 0x11, 0xae },
                                     { 0xe0, 0xbf, 0x98, 0xf1 },
                                     { 0xb8, 0xb4, 0x5d, 0xe5 },
                                     { 0x1e, 0x41, 0x52, 0x30 } };

            TestStateResult = new byte[,] {{ 0xd4, 0xbf, 0x5d, 0x30},
                                           { 0xe0, 0xb4, 0x52, 0xae},
                                           { 0xb8, 0x41, 0x11, 0xf1},
                                           { 0x1e, 0x27, 0x98, 0xe5}};
            aesTest.state = TestState;

            aesTest.shiftRows();

            var result = aesTest.state;

            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    Assert.IsTrue(result[i, j] == TestStateResult[i, j]);
                }
            }
        }

        [TestMethod]
        public void addRoundKeyTestFirst()
        {
            TestState = new byte[,] { { 0x32, 0x43, 0xf6, 0xa8 },
                                      { 0x88, 0x5a, 0x30, 0x8d},
                                      { 0x31, 0x31, 0x98, 0xa2 },
                                      { 0xe0, 0x37, 0x07, 0x34} };

            byte[,] testKey = new byte[4, 4] {  {0x2b, 0x7e, 0x15, 0x16 },
                                                {0x28, 0xae, 0xd2, 0xa6},
                                                {0xab, 0xf7, 0x15, 0x88},
                                                {0x09, 0xcf, 0x4f, 0x3c} };

            var CorrectResult = new byte[,] {{ 0x19, 0x3d, 0xe3, 0xbe },
                                             { 0xa0, 0xf4, 0xe2, 0x2b },
                                             { 0x9a, 0xc6, 0x8d, 0x2a },
                                             { 0xe9, 0xf8, 0x48, 0x08 } };

            aesTest.state = TestState;
            aesTest.key = testKey;

            aesTest.expandKey();

            aesTest.addRoundKey();

            var result = aesTest.state;

            for (int i = 0; i < 4; i++)
            {
                for (int d = 0; d < 4; d++)
                {
                    Assert.IsTrue(result[i, d] == CorrectResult[i, d]);
                }
            }
        }

        [TestMethod]
        public void cipherTestRound1()
        {
            var Input = new byte[] { 0x32, 0x43, 0xf6, 0xa8,
                                     0x88, 0x5a, 0x30, 0x8d,
                                     0x31, 0x31, 0x98, 0xa2,
                                     0xe0, 0x37, 0x07, 0x34 };

            byte[] Cipher_Key = new byte[] {0x2b, 0x7e, 0x15, 0x16,
                                                0x28, 0xae, 0xd2, 0xa6,
                                                0xab, 0xf7, 0x15, 0x88,
                                                0x09, 0xcf, 0x4f, 0x3c };

            var RoundOneState = new byte[,] {{ 0x19, 0x3d, 0xe3, 0xbe },
                                             { 0xa0, 0xf4, 0xe2, 0x2b },
                                             { 0x9a, 0xc6, 0x8d, 0x2a },
                                             { 0xe9, 0xf8, 0x48, 0x08 } };

            var cipher = aesTest.Encrypt(Input, Cipher_Key, Constants.EncryptionMode.AES128, 1);

            for (int i = 0; i < 4; i++)
            {
                for (int d = 0; d < 4; d++)
                {
                    Assert.IsTrue(cipher[i, d] == RoundOneState[i, d]);
                }
            }
        }

        [TestMethod]
        public void cipherTestRound5()
        {
            var Input = new byte[] { 0x32, 0x43, 0xf6, 0xa8,
                                     0x88, 0x5a, 0x30, 0x8d,
                                     0x31, 0x31, 0x98, 0xa2,
                                     0xe0, 0x37, 0x07, 0x34 };

            byte[] Cipher_Key = new byte[] {0x2b, 0x7e, 0x15, 0x16,
                                                0x28, 0xae, 0xd2, 0xa6,
                                                0xab, 0xf7, 0x15, 0x88,
                                                0x09, 0xcf, 0x4f, 0x3c };

            var RoundOneState = new byte[,] {{ 0xe0, 0x92, 0x7f, 0xe8 },
                                             { 0xc8, 0x63, 0x63, 0xc0 },
                                             { 0xd9, 0xb1, 0x35, 0x50 },
                                             { 0x85, 0xb8, 0xbe, 0x01 } };

            var cipher = aesTest.Encrypt(Input, Cipher_Key, Constants.EncryptionMode.AES128, 5);

            for (int i = 0; i < 4; i++)
            {
                for (int d = 0; d < 4; d++)
                {
                    Assert.IsTrue(cipher[i, d] == RoundOneState[i, d]);
                }
            }
        }

        [TestMethod]
        public void cipherTestRoundComplete()
        {
            var Input = new byte[] { 0x32, 0x43, 0xf6, 0xa8,
                                     0x88, 0x5a, 0x30, 0x8d,
                                     0x31, 0x31, 0x98, 0xa2,
                                     0xe0, 0x37, 0x07, 0x34 };

            byte[] Cipher_Key = new byte[] {0x2b, 0x7e, 0x15, 0x16,
                                                0x28, 0xae, 0xd2, 0xa6,
                                                0xab, 0xf7, 0x15, 0x88,
                                                0x09, 0xcf, 0x4f, 0x3c };

            var RoundOneState = new byte[,] {{ 0x39, 0x25, 0x84, 0x1d },
                                             { 0x02, 0xdc, 0x09, 0xfb },
                                             { 0xdc, 0x11, 0x85, 0x97 },
                                             { 0x19, 0x6a, 0x0b, 0x32 } };

            var cipher = aesTest.Encrypt(Input, Cipher_Key, Constants.EncryptionMode.AES128);

            for (int i = 0; i < 4; i++)
            {
                for (int d = 0; d < 4; d++)
                {
                    Assert.IsTrue(cipher[i, d] == RoundOneState[i, d]);
                }
            }
        }
    }
}
