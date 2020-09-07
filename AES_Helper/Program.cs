using System;
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
            AES aesCipher = new AES(Constants.EncryptionMode.AES128);
            //byte[] Input = new byte[] { 0x32, 0x43, 0xf6, 0xa8 , 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34 };

            //byte[] Cipher_Key = new byte[] { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
            byte[] Input128Bit = new byte[] { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };

            byte[] Cipher_Key128Bit = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

            Console.Write("Plantest:            ");
            for (int i = 0; i < Input128Bit.Length; i++)
            {
                Console.Write("{0:X}", Input128Bit[i]);
            }
            Console.WriteLine();
            Console.Write("Key:                 ");
            for (int i = 0; i < Cipher_Key128Bit.Length; i++)
            {
                Console.Write("{0:X}", Cipher_Key128Bit[i]);
            }
            Console.WriteLine();
            Console.WriteLine();
            Console.WriteLine();

            var cipher = aesCipher.Encrypt(Input128Bit, Cipher_Key128Bit, Constants.EncryptionMode.AES128);


            Console.ReadLine();
        }
    }
}
