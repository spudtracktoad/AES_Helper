﻿using System;
using AESEncryption;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace AES_Tests
{
    [TestClass]
    public class KeyExpansion256
    {
        AES aesTest;
        byte[,] KeyMaster = new byte[60, 4] {{ 0x60, 0x3d, 0xeb, 0x10}, { 0x15, 0xca, 0x71, 0xbe}, { 0x2b, 0x73, 0xae, 0xf0}, { 0x85, 0x7d, 0x77, 0x81}, { 0x1f, 0x35, 0x2c, 0x07}, { 0x3b, 0x61, 0x08, 0xd7}, { 0x2d, 0x98, 0x10, 0xa3}, { 0x09, 0x14, 0xdf, 0xf4},
            {0x9b, 0xa3, 0x54, 0x11}, {0x8e, 0x69, 0x25, 0xaf}, {0xa5, 0x1a, 0x8b, 0x5f}, {0x20, 0x67, 0xfc, 0xde}, {0xa8, 0xb0, 0x9c, 0x1a}, {0x93, 0xd1, 0x94, 0xcd}, {0xbe, 0x49, 0x84, 0x6e}, {0xb7, 0x5d, 0x5b, 0x9a}, {0xd5, 0x9a, 0xec, 0xb8}, {0x5b, 0xf3, 0xc9, 0x17},
            {0xfe, 0xe9, 0x42, 0x48}, {0xde, 0x8e, 0xbe, 0x96}, {0xb5, 0xa9, 0x32, 0x8a}, {0x26, 0x78, 0xa6, 0x47}, {0x98, 0x31, 0x22, 0x29}, {0x2f, 0x6c, 0x79, 0xb3}, {0x81, 0x2c, 0x81, 0xad}, {0xda, 0xdf, 0x48, 0xba}, {0x24, 0x36, 0x0a, 0xf2}, {0xfa, 0xb8, 0xb4, 0x64},
            {0x98, 0xc5, 0xbf, 0xc9}, {0xbe, 0xbd, 0x19, 0x8e}, {0x26, 0x8c, 0x3b, 0xa7}, {0x09, 0xe0, 0x42, 0x14}, {0x68, 0x00, 0x7b, 0xac}, {0xb2, 0xdf, 0x33, 0x16}, {0x96, 0xe9, 0x39, 0xe4}, {0x6c, 0x51, 0x8d, 0x80}, {0xc8, 0x14, 0xe2, 0x04}, {0x76, 0xa9, 0xfb, 0x8a},
            {0x50, 0x25, 0xc0, 0x2d}, {0x59, 0xc5, 0x82, 0x39}, {0xde, 0x13, 0x69, 0x67}, {0x6c, 0xcc, 0x5a, 0x71}, {0xfa, 0x25, 0x63, 0x95}, {0x96, 0x74, 0xee, 0x15}, {0x58, 0x86, 0xca, 0x5d}, {0x2e, 0x2f, 0x31, 0xd7}, {0x7e, 0x0a, 0xf1, 0xfa},{0x27, 0xcf, 0x73, 0xc3},
            {0x74, 0x9c, 0x47, 0xab}, {0x18, 0x50, 0x1d, 0xda}, {0xe2, 0x75, 0x7e, 0x4f}, {0x74, 0x01, 0x90, 0x5a}, {0xca, 0xfa, 0xaa, 0xe3}, {0xe4, 0xd5, 0x9b, 0x34}, {0x9a, 0xdf, 0x6a, 0xce}, {0xbd, 0x10, 0x19, 0x0d}, {0xfe, 0x48, 0x90, 0xd1}, {0xe6, 0x18, 0x8d, 0x0b},
            {0x04, 0x6d, 0xf3, 0x44}, {0x70, 0x6c, 0x63, 0x1e } };


        [TestInitialize]
        public void setup()
        {
            aesTest = new AES(Constants.EncryptionMode.AES256);
            byte[,] testKey = new byte[,]
            {{ 0x60, 0x3d, 0xeb, 0x10},
            { 0x15, 0xca, 0x71, 0xbe},
            { 0x2b, 0x73, 0xae, 0xf0},
            { 0x85, 0x7d, 0x77, 0x81},
            { 0x1f, 0x35, 0x2c, 0x07},
            { 0x3b, 0x61, 0x08, 0xd7},
            { 0x2d, 0x98, 0x10, 0xa3},
            { 0x09, 0x14, 0xdf, 0xf4} };

            aesTest.key = testKey;
        }

        [TestMethod]
        public void ExpandKeyInitial()
        {
            aesTest.expandKey();

            var resultKey = aesTest.keySchedule;

            Assert.IsTrue(resultKey[0, 0] == 0x60);
            Assert.IsTrue(resultKey[0, 1] == 0x3d);
            Assert.IsTrue(resultKey[0, 2] == 0xeb);
            Assert.IsTrue(resultKey[0, 3] == 0x10);
        }

        [TestMethod]
        public void ExpandKeyRnd6()
        {
            aesTest.expandKey();

            var resultKey = aesTest.keySchedule;

            Assert.IsTrue(resultKey[8, 0] == 0x9b);
            Assert.IsTrue(resultKey[8, 1] == 0xa3);
            Assert.IsTrue(resultKey[8, 2] == 0x54);
            Assert.IsTrue(resultKey[8, 3] == 0x11);
        }

        [TestMethod]
        public void ExpandKeyComplete()
        {
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
