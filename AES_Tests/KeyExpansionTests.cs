﻿using System;
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
        public void subWordTest()
        {
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
    }
}
