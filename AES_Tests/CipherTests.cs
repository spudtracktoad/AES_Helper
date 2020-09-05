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
            aesTest = new AES();
        }

        [TestMethod]
        public void mixColumnsTest()
        {
            TestState = new byte[,] {{ 0xd4, 0xe0, 0xb8, 0x1e },
                                         { 0xbf, 0xb4, 0x41, 0x27 },
                                         { 0x5d, 0x52, 0x11, 0x98 },
                                         { 0x30, 0xae, 0xf1, 0xe5 } };

            TestStateResult = new byte[,] {{ 0x04, 0xe0, 0x48, 0x28 },
                                               { 0x66, 0xcb, 0xf8, 0x06 },
                                               { 0x81, 0x19, 0xd3, 0x26 },
                                               { 0xe5, 0x9a, 0x7a, 0x4c } };

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
        public void shiftWordsTest()
        {

            TestState = new byte[,] {{ 0x19, 0xa0, 0x9a, 0xe9 },
                                         { 0x3d, 0xf4, 0xc6, 0xf8 },
                                         { 0xe3, 0xe2, 0x8d, 0x48 },
                                         { 0xbe, 0x2b, 0x2a, 0x08 } };

            TestStateResult = new byte[,] {{ 0x19, 0xa0, 0x9a, 0xe9 },
                                         { 0xf4, 0xc6, 0xf8, 0x3d },
                                         { 0x8d, 0x48, 0xe3, 0xe2 },
                                         { 0x08, 0xbe, 0x2b, 0x2a } };
            aesTest.state = TestState;


            aesTest.shiftRows();

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
        public void shiftRwoTest()
        {

            TestState = new byte[,] {{ 0x19, 0xa0, 0x9a, 0xe9 },
                                         { 0x3d, 0xf4, 0xc6, 0xf8 },
                                         { 0xe3, 0xe2, 0x8d, 0x48 },
                                         { 0xbe, 0x2b, 0x2a, 0x08 } };

            TestStateResult = new byte[,] {{ 0x19, 0xa0, 0x9a, 0xe9 },
                                           { 0xf4, 0xc6, 0xf8, 0x3d },
                                           { 0x8d, 0x48, 0xe3, 0xe2 },
                                           { 0x08, 0xbe, 0x2b, 0x2a } };
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
        public void addRoundKeyTest()
        {
            TestState = new byte[,] {{ 0x04, 0xe0, 0x48, 0x28 },
                                     { 0x66, 0xcb, 0xf8, 0x06 },
                                     { 0x81, 0x19, 0xd3, 0x26 },
                                     { 0xe5, 0x9a, 0x7a, 0x4c } };

            byte[,] testKey = new byte[4, 4] {  {0x2b, 0x7e, 0x15, 0x16 },
                                                {0x28, 0xae, 0xd2, 0xa6},
                                                {0xab, 0xf7, 0x15, 0x88},
                                                {0x09, 0xcf, 0x4f, 0x3c} };

            var CorrectResult = new byte[,] {{ 0xa4, 0x68, 0x6b, 0x02 },
                                             { 0x9c, 0x9f, 0x5b, 0x6a },
                                             { 0x7f, 0x35, 0xea, 0x50 },
                                             { 0xf2, 0x2b, 0x43, 0x49 } };

            aesTest.state = TestState;
            aesTest.key = testKey;

            aesTest.expandKey();
            aesTest.round = 4;

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

            byte[] Input = new byte[] { 0x32, 0x43, 0xf6, 0xa8, 
                                         0x88, 0x5a, 0x30, 0x8d, 
                                         0x31, 0x31, 0x98, 0xa2, 
                                         0xe0, 0x37, 0x07, 0x34 };

            byte[] Cipher_Key = new byte[] { 0x2b, 0x7e, 0x15, 0x16, 
                                              0x28, 0xae, 0xd2, 0xa6, 
                                              0xab, 0xf7, 0x15, 0x88, 
                                              0x09, 0xcf, 0x4f, 0x3c };

            byte[,] RoundOneState = new byte[,] { { 0x19, 0xa0, 0x9a, 0xe9 },
                                                  { 0x3d, 0xf4, 0xc6, 0xf8 },
                                                  { 0xe3, 0xe2, 0x8d, 0x48 },
                                                  { 0xbe, 0x2b, 0x2a, 0x08 } };  

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
