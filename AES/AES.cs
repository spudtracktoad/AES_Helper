using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AESEncryption
{
    public class AES
    {
        private const byte XORBYTE = 0x1b;
        private const byte HIGHBIT = 0x80;
        private static readonly byte[] MCRONE = { 0x02, 0x03, 0x01, 0x01 };
        private static readonly byte[] MCRTWO = { 0x01, 0x02, 0x03, 0x01 };
        private static readonly byte[] MCRTHREE = { 0x01, 0x01, 0x02, 0x03 };
        private static readonly byte[] MCRFOUR = { 0x03, 0x01, 0x01, 0x02 };


        private byte[][] State = new byte[4][];

        #region helpers for test

        public void setState(byte[][] input)
        {
            State = input;
        }

        public byte[][] getState()
        {
            return State;
        }

        #region Finite Field 
        public byte ffAdd(byte a, byte b)
        {
            byte[] result = new byte[4];
            result = BitConverter.GetBytes(a ^ b);

            return result[0];
        }

        public byte xTime(byte input)
        {
            byte[] result = new byte[4];
            int test = input << 1;
            result = BitConverter.GetBytes(input << 1);
            if ((input & HIGHBIT) == 0x80)
                result[0] = Convert.ToByte(result[0] ^ XORBYTE);

            return result[0];
        }

        public byte ffMultiply(byte multiplicand, byte multiplier)
        {
            byte[] result = new byte[4];
            byte temp = multiplicand;

            for (int i = 0; i < 8; i++)
            {
                if ((multiplier & (1 << (i))) == (1<<i))
                {
                    result = BitConverter.GetBytes(result[0] ^ temp);
                }
                temp = xTime(temp);
            }
            return result[0];

        }

        #endregion

        #region Cipher

        public void mixColumns()
        {

        }

        #endregion
    }
}
