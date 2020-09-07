﻿using System;
using AESEncryption;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace AES_Tests
{
    [TestClass]
    public class KeyExpansionTest192
    {
        AES aesTest;
        byte[,] KeyMaster = new byte[52, 4] {  { 0x8e, 0x73, 0xb0, 0xf7 }, { 0xda, 0x0e, 0x64, 0x52 }, { 0xc8, 0x10, 0xf3, 0x2b }, { 0x80, 0x90, 0x79, 0xe5 }, { 0x62, 0xf8, 0xea, 0xd2 }, { 0x52, 0x2c, 0x6b, 0x7b }, {0xfe, 0x0c, 0x91, 0xf7}, 
                                               {0x24, 0x02, 0xf5, 0xa5}, {0xec, 0x12, 0x06, 0x8e}, {0x6c, 0x82, 0x7f, 0x6b}, {0x0e, 0x7a, 0x95, 0xb9}, {0x5c, 0x56, 0xfe, 0xc2}, {0x4d, 0xb7, 0xb4, 0xbd}, {0x69, 0xb5, 0x41, 0x18}, {0x85, 0xa7, 0x47, 0x96},
                                               {0xe9, 0x25, 0x38, 0xfd}, {0xe7, 0x5f, 0xad, 0x44}, {0xbb, 0x09, 0x53, 0x86}, {0x48, 0x5a, 0xf0, 0x57}, {0x21, 0xef, 0xb1, 0x4f}, {0xa4, 0x48, 0xf6, 0xd9}, {0x4d, 0x6d, 0xce, 0x24}, {0xaa, 0x32, 0x63, 0x60},
                                               {0x11, 0x3b, 0x30, 0xe6}, {0xa2, 0x5e, 0x7e, 0xd5}, {0x83, 0xb1, 0xcf, 0x9a}, {0x27, 0xf9, 0x39, 0x43}, {0x6a, 0x94, 0xf7, 0x67}, {0xc0, 0xa6, 0x94, 0x07}, {0xd1, 0x9d, 0xa4, 0xe1}, {0xec, 0x17, 0x86, 0xeb},
                                               {0x6f, 0xa6, 0x49, 0x71}, {0x48, 0x5f, 0x70, 0x32}, {0x22, 0xcb, 0x87, 0x55}, {0xe2, 0x6d, 0x13, 0x52}, {0x33, 0xf0, 0xb7, 0xb3}, {0x40, 0xbe, 0xeb, 0x28}, {0x2f, 0x18, 0xa2, 0x59}, {0x67, 0x47, 0xd2, 0x6b},
                                               {0x45, 0x8c, 0x55, 0x3e}, {0xa7, 0xe1, 0x46, 0x6c}, {0x94, 0x11, 0xf1, 0xdf}, {0x82, 0x1f, 0x75, 0x0a}, {0xad, 0x07, 0xd7, 0x53}, {0xca, 0x40, 0x05, 0x38}, {0x8f, 0xcc, 0x50, 0x06}, {0x28, 0x2d, 0x16, 0x6a},
                                               {0xbc, 0x3c, 0xe7, 0xb5}, {0xe9, 0x8b, 0xa0, 0x6f}, {0x44, 0x8c, 0x77, 0x3c}, {0x8e, 0xcc, 0x72, 0x04}, {0x01, 0x00, 0x22, 0x02} };

        [TestInitialize]
        public void setup()
        {
            aesTest = new AES(Constants.EncryptionMode.AES192);
        }

        [TestMethod]
        public void ExpandKeyInitial()
        {
            byte[,] testKey = new byte[,] { { 0x8e, 0x73, 0xb0, 0xf7 }, 
                                            { 0xda, 0x0e, 0x64, 0x52 }, 
                                            { 0xc8, 0x10, 0xf3, 0x2b },
                                            { 0x80, 0x90, 0x79, 0xe5 },
                                            { 0x62, 0xf8, 0xea, 0xd2 },
                                            { 0x52, 0x2c, 0x6b, 0x7b } };

            aesTest.key = testKey;

            aesTest.expandKey();

            var resultKey = aesTest.keySchedule;

            Assert.IsTrue(resultKey[0, 0] == 0x8e);
            Assert.IsTrue(resultKey[0, 1] == 0x73);
            Assert.IsTrue(resultKey[0, 2] == 0xb0);
            Assert.IsTrue(resultKey[0, 3] == 0xf7);
        }

        [TestMethod]
        public void ExpandKeyRnd6()
        {
            byte[,] testKey = new byte[,] { { 0x8e, 0x73, 0xb0, 0xf7 },
                                            { 0xda, 0x0e, 0x64, 0x52 },
                                            { 0xc8, 0x10, 0xf3, 0x2b },
                                            { 0x80, 0x90, 0x79, 0xe5 },
                                            { 0x62, 0xf8, 0xea, 0xd2 },
                                            { 0x52, 0x2c, 0x6b, 0x7b } };

            aesTest.key = testKey;

            aesTest.expandKey();

            var resultKey = aesTest.keySchedule;

            Assert.IsTrue(resultKey[6, 0] == 0xfe);
            Assert.IsTrue(resultKey[6, 1] == 0x0c);
            Assert.IsTrue(resultKey[6, 2] == 0x91);
            Assert.IsTrue(resultKey[6, 3] == 0xf7);
        }

        [TestMethod]
        public void ExpandKeyComplete()
        {
            byte[,] testKey = new byte[,] { { 0x8e, 0x73, 0xb0, 0xf7 },
                                            { 0xda, 0x0e, 0x64, 0x52 },
                                            { 0xc8, 0x10, 0xf3, 0x2b },
                                            { 0x80, 0x90, 0x79, 0xe5 },
                                            { 0x62, 0xf8, 0xea, 0xd2 },
                                            { 0x52, 0x2c, 0x6b, 0x7b } };

            aesTest.key = testKey;

            aesTest.expandKey();

            var resultKey = aesTest.keySchedule;

            for (int i = 0; i < 52; i++)
            {
                for (int d = 0; d < 4; d++)
                {
                    Assert.IsTrue(resultKey[i, d] == KeyMaster[i, d]);
                }
            }
        }
    }
}
