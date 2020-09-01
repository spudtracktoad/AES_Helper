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

        [TestInitialize]
        public void setup()
        {
            aesTest = new AES();

            TestState = new byte[,] {{ 0x19, 0xa0, 0x9a, 0xe9 },
                                         { 0x3d, 0xf4, 0xc6, 0xf8 },
                                         { 0xe3, 0xe2, 0x8d, 0x48 },
                                         { 0xbe, 0x2b, 0x2a, 0x08 } };

            TestStateResult = new byte[,] {{ 0xd4, 0xe0, 0xb8, 0x1e },
                                               { 0x27, 0xbf, 0xb4, 0x41 },
                                               { 0x11, 0x98, 0x5d, 0x52 },
                                               { 0xae, 0xf1, 0xe5, 0x30 } };

            aesTest.state = TestState;
        }

        [TestMethod]
        public void subWordTestZero()
        {
            var result = aesTest.subWord(0x00102030);

            Assert.IsTrue(result == 0x63cab704);
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
            var result = aesTest.rotWord(0x09cf4f3c);

            Assert.IsTrue(result == 0xcf4f3c09);
        }

        [TestMethod]
        public void rotWordTestTwo()
        {
            var result = aesTest.rotWord(0x2a6c7605);

            Assert.IsTrue(result == 0x6c76052a);
        }
    }
}
