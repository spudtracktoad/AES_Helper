﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using AESEncryption;

namespace AES_Helper
{
    class Program
    {
        static void Main(string[] args)
        {
            AES aesCipher = new AES();
            byte[] Input = new byte[] { 0x32, 0x43, 0xf6, 0xa8 , 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34 };

            byte[] Cipher_Key = new byte[] { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };

            var cipher = aesCipher.Encrypt(Input, Cipher_Key, Constants.EncryptionMode.AES128);

        }
    }
}
