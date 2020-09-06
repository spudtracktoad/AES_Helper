using System;
using AESEncryption;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace AES_Tests
{
    [TestClass]
    public class KeyExpansionTests
    {
        AES aesTest;
        byte[,] TestState;
        byte[,] TestStateResult;
        byte[,] TestKeyScheduleCorrect = new byte[,] { { 0x2b, 0x7e, 0x15, 0x16 }, { 0x28, 0xae, 0xd2, 0xa6 }, { 0xab, 0xf7, 0x15, 0x88 }, { 0x09, 0xcf, 0x4f, 0x3c, }, {0xa0, 0xfa, 0xfe, 0x17}, {0x88, 0x54, 0x2c, 0xb1}, {0x23, 0xa3, 0x39, 0x39},
                                                        {0x2a, 0x6c, 0x76, 0x05}, {0xf2, 0xc2, 0x95, 0xf2}, {0x7a, 0x96, 0xb9, 0x43}, {0x59, 0x35, 0x80, 0x7a}, {0x73, 0x59, 0xf6, 0x7f}, {0x3d, 0x80, 0x47, 0x7d}, {0x47, 0x16, 0xfe, 0x3e}, {0x1e, 0x23, 0x7e, 0x44},
                                                        {0x6d, 0x7a, 0x88, 0x3b}, {0xef, 0x44, 0xa5, 0x41}, {0xa8, 0x52, 0x5b, 0x7f}, {0xb6, 0x71, 0x25, 0x3b}, {0xdb, 0x0b, 0xad, 0x00}, {0xd4, 0xd1, 0xc6, 0xf8}, {0x7c, 0x83, 0x9d, 0x87}, {0xca, 0xf2, 0xb8, 0xbc},
                                                        {0x11, 0xf9, 0x15, 0xbc}, {0x6d, 0x88, 0xa3, 0x7a}, {0x11, 0x0b, 0x3e, 0xfd}, {0xdb, 0xf9, 0x86, 0x41}, {0xca, 0x00, 0x93, 0xfd}, {0x4e, 0x54, 0xf7, 0x0e}, {0x5f, 0x5f, 0xc9, 0xf3}, {0x84, 0xa6, 0x4f, 0xb2},
                                                        {0x4e, 0xa6, 0xdc, 0x4f}, {0xea, 0xd2, 0x73, 0x21}, {0xb5, 0x8d, 0xba, 0xd2}, {0x31, 0x2b, 0xf5, 0x60}, {0x7f, 0x8d, 0x29, 0x2f}, {0xac, 0x77, 0x66, 0xf3}, {0x19, 0xfa, 0xdc, 0x21}, {0x28, 0xd1, 0x29, 0x41},
                                                        {0x57, 0x5c, 0x00, 0x6e}, {0xd0, 0x14, 0xf9, 0xa8}, {0xc9, 0xee, 0x25, 0x89}, {0xe1, 0x3f, 0x0c, 0xc8}, {0xb6, 0x63, 0x0c, 0xa6}};

        [TestInitialize]
        public void setup()
        {
            aesTest = new AES();

            //TestState = new byte[,] {{ 0x19, 0xa0, 0x9a, 0xe9 },
            //                             { 0x3d, 0xf4, 0xc6, 0xf8 },
            //                             { 0xe3, 0xe2, 0x8d, 0x48 },
            //                             { 0xbe, 0x2b, 0x2a, 0x08 } };

            //TestStateResult = new byte[,] {{ 0xd4, 0xe0, 0xb8, 0x1e },
            //                                   { 0x27, 0xbf, 0xb4, 0x41 },
            //                                   { 0x11, 0x98, 0x5d, 0x52 },
            //                                   { 0xae, 0xf1, 0xe5, 0x30 } };

            //aesTest.state = TestState;
        }

        [TestMethod]
        public void subWordTestZero()
        {
            byte[] word = new byte[] { 0x00, 0x10, 0x20, 0x30 };
            var result = aesTest.subWord(word);

            Assert.IsTrue(result[0] == 0x63);
            Assert.IsTrue(result[1] == 0xca);
            Assert.IsTrue(result[2] == 0xb7);
            Assert.IsTrue(result[3] == 0x04);
        }

        [TestMethod]
        public void subWordTestOne()
        {
            var result = aesTest.subWord(0x40506070);

            Assert.IsTrue(result == 0x0953d051);
        }

        [TestMethod]
        public void subWordTestTwo()
        {
            var result = aesTest.subWord(0x8090a0b0);

            Assert.IsTrue(result == 0xcd60e0e7);
        }

        [TestMethod]
        public void subWordTestThree()
        {
            var result = aesTest.subWord(0xc0d0e0f0);

            Assert.IsTrue(result == 0xba70e18c);
        }

        [TestMethod]
        public void rotWordTestOne()
        {
            byte[] word = new byte[] { 0x09, 0xcf, 0x4f, 0x3c};
            var result = aesTest.rotWord(word);

            Assert.IsTrue(result[0] == 0xcf);
            Assert.IsTrue(result[1] == 0x4f);
            Assert.IsTrue(result[2] == 0x3c);
            Assert.IsTrue(result[3] == 0x09);
        }

        [TestMethod]
        public void rotWordTestTwo()
        {
            byte[] word = new byte[] { 0x2a, 0x6c, 0x76, 0x05 };
            var result = aesTest.rotWord(word);

            Assert.IsTrue(result[0] == 0x6c);
            Assert.IsTrue(result[1] == 0x76);
            Assert.IsTrue(result[2] == 0x05);
            Assert.IsTrue(result[3] == 0x2a);
        }

        [TestMethod]
        public void KeyExpansionTestBase()
        {
            byte[,] testKey = new byte[,] { { 0x2b, 0x7e, 0x15, 0x16 },{ 0x28, 0xae, 0xd2, 0xa6 }, { 0xab, 0xf7, 0x15, 0x88 }, {0x09, 0xcf, 0x4f, 0x3c } };

            aesTest.key = testKey;

            aesTest.expandKey();

            var resultKey = aesTest.keySchedule;

            Assert.IsTrue(resultKey[0, 0] == 0x2b);
            Assert.IsTrue(resultKey[0, 1] == 0x7e);
            Assert.IsTrue(resultKey[0, 2] == 0x15);
            Assert.IsTrue(resultKey[0, 3] == 0x16);
        }
        
        [TestMethod]
        public void KeyExpansionTest()
        {
            byte[,] testKey = new byte[,] { { 0x2b, 0x7e, 0x15, 0x16 }, { 0x28, 0xae, 0xd2, 0xa6 }, { 0xab, 0xf7, 0x15, 0x88 }, { 0x09, 0xcf, 0x4f, 0x3c } };

            aesTest.key = testKey;

            aesTest.expandKey();

            var resultKey = aesTest.keySchedule;

            Assert.IsTrue(resultKey[4, 0] == 0xa0);
            Assert.IsTrue(resultKey[4, 1] == 0xfa);
            Assert.IsTrue(resultKey[4, 2] == 0xfe);
            Assert.IsTrue(resultKey[4, 3] == 0x17);
        }

        [TestMethod]
        public void KeyExpansionTestFull()
        {
            byte[,] testKey = new byte[,] { { 0x2b, 0x7e, 0x15, 0x16 }, { 0x28, 0xae, 0xd2, 0xa6 }, { 0xab, 0xf7, 0x15, 0x88 }, { 0x09, 0xcf, 0x4f, 0x3c } };

            byte[,] resultKey = new byte[4, 44];

            aesTest.key = testKey;

            aesTest.expandKey();

            resultKey = aesTest.keySchedule;

            for (int i = 0; i < 44; i++)
            {
                for (int d = 0; d < 4; d++)
                {
                    Assert.IsTrue(resultKey[i,d] == TestKeyScheduleCorrect[i,d]);
                }
            }
        }
    }
}
