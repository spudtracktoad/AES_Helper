using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using AESEncryption;

namespace AES_Tests
{
    [TestClass]
    public class finitefieldarithmetic
    {
        AES test;

        [TestInitialize]
        public void initTest()
        {
            test = new AES();
        }

        [TestCleanup]
        public void cleanupTest()
        {
            
        }

        [TestMethod]
        public void ffAddTest()
        {
            Assert.IsTrue(test.ffAdd(0x57, 0x83) == 0xd4);
        }

        [TestMethod]
        public void ffMultiplyTest()
        {
            Assert.IsTrue(test.ffMultiply(0x57,0x13) == 0xfe);
        }

        [TestMethod]
        public void xTimeTestOne()
        {
            AES test = new AES();

            Assert.IsTrue(test.xTime(0x57) == 0xae);
        }

        [TestMethod]
        public void xTimeTestTwo()
        {
            Assert.IsTrue(test.xTime(0xae) == 0x47);
        }

        [TestMethod]
        public void xTimeTestThree()
        {
            Assert.IsTrue(test.xTime(0x47) == 0x8e);
        }

        [TestMethod]
        public void xTimeTestFour()
        {
            Assert.IsTrue(test.xTime(0x8e) == 0x07);
        }
    }
}
