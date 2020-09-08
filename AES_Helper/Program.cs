using System;
using System.Collections.Generic;
using System.Data;
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
            byte[] PLAINTEXT128Bit = new byte[] { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
            byte[] CIPHERTEXT128 = new byte[] { 0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a };
            byte[] KEY128Bit = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

            byte[] PLAINTEXT192Bit = new byte[] { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
            byte[] KEY192Bit = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 };

            byte[] PLAINTEXT256Bit = new byte[] { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
            byte[] KEY256Bit = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };
           
            #region 128Bit

            Console.WriteLine("128 Bit");
            Console.Write("Plantest:            ");
            for (int i = 0; i < PLAINTEXT128Bit.Length; i++)
            {
                Console.Write("{0:X}", KEY128Bit[i]);
            }
            Console.WriteLine();
            Console.Write("Key:                 ");
            for (int i = 0; i < KEY128Bit.Length; i++)
            {
                Console.Write("{0:X}", KEY128Bit[i]);
            }

            var cipher = aesCipher.Encrypt(PLAINTEXT128Bit, KEY128Bit, Constants.EncryptionMode.AES128);

            Console.WriteLine();
            Console.WriteLine();
            Console.WriteLine();

            cipher = aesCipher.Decrypt(CIPHERTEXT128, KEY128Bit, Constants.EncryptionMode.AES128);

            Console.WriteLine();
            Console.WriteLine();
            Console.WriteLine();

            #endregion
            #region 192BIT

            aesCipher.mode = Constants.EncryptionMode.AES192;

            Console.WriteLine("192 Bit");
            Console.Write("Plantest:            ");
            for (int i = 0; i < PLAINTEXT192Bit.Length; i++)
            {
                Console.Write("{0:X}", PLAINTEXT192Bit[i]);
            }
            Console.WriteLine();
            Console.Write("Key:                 ");
            for (int i = 0; i < KEY192Bit.Length; i++)
            {
                Console.Write("{0:X}", KEY192Bit[i]);
            }

            var cipher192 = aesCipher.Encrypt(PLAINTEXT192Bit, KEY192Bit, Constants.EncryptionMode.AES192);

            Console.WriteLine();
            Console.WriteLine();
            Console.WriteLine();
            #endregion
            #region 256BIT
            aesCipher.mode = Constants.EncryptionMode.AES256;

            Console.WriteLine("256 Bit");
            Console.Write("Plantest:            ");
            for (int i = 0; i < PLAINTEXT256Bit.Length; i++)
            {
                Console.Write("{0:X}", PLAINTEXT256Bit[i]);
            }
            Console.WriteLine();
            Console.Write("Key:                 ");
            for (int i = 0; i < KEY192Bit.Length; i++)
            {
                Console.Write("{0:X}", KEY256Bit[i]);
            }

            var cipher256 = aesCipher.Encrypt(PLAINTEXT256Bit, KEY256Bit, Constants.EncryptionMode.AES256);
            Console.WriteLine();
            Console.WriteLine();
            Console.WriteLine();
            #endregion

            Console.ReadLine();
        }
    }
}
