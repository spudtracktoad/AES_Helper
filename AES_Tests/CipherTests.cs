using AESEncryption;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
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
    }
}
