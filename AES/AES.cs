using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

namespace AESEncryption
{
    public class AES
    {

        private byte[,] State = new byte[4,4];

        #region helpers for test

        public byte[,] state 
        {
            get { return State; }
            set { State = value; }
        }
        #endregion

        #region KeyExpansion

        public uint subWord(uint word)
        {
            uint result;
            byte[] tmpBytes = BitConverter.GetBytes(word);

            for (int i = 0; i < 4; i++)
            {
                tmpBytes[i] = subByte(tmpBytes[i]);
            }

            result = BitConverter.ToUInt32(tmpBytes, 0);

            return result;
        }

        public uint rotWord(uint word)
        {
            uint result;
            byte[] tmpBytes = BitConverter.GetBytes(word);
            byte tmpByte;

            tmpByte = tmpBytes[3];
            tmpBytes[3] = tmpBytes[2];
            tmpBytes[2] = tmpBytes[1];
            tmpBytes[1] = tmpBytes[0];
            tmpBytes[0] = tmpByte;

            result = BitConverter.ToUInt32(tmpBytes, 0);
            return result;
        }


        #endregion

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
            if ((input & Constants.HIGHBIT) == 0x80)
                result[0] = Convert.ToByte(result[0] ^ Constants.XORBYTE);

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

        public void subBytes()
        {
            for (int i = 0; i < 4; i++)
            {
                for (int d = 0; d < 4; d++)
                {
                    state[i, d] = subByte(state[i, d]);
                }
            }
        }

        public void mixColumns()
        {
            var tmpState = new byte[4, 4];
            for (int Col = 0; Col < 4; Col++)
            {
                for (int row = 0; row < 4; row++)
                {
                    tmpState[row, Col] = CalcMixColumn(row, Col);
                }
            }
            State = tmpState;
        }

        public void shiftRows()
        {
            for (int row = 1; row < 4; row++)
            {
                shiftRow( row);
            }
        }
        #endregion

        #region Helper Private
        private byte CalcMixColumn(int row, int col)
        {
            byte[] result= new byte[4];

            for (int index = 0; index < 4; index++)
            {
                if (Constants.ColmnsMixArray[row, index] == 0x1)
                    result = BitConverter.GetBytes(result[0] ^ State[index, col]);
                if (Constants.ColmnsMixArray[row, index] == 0x2)
                    result = BitConverter.GetBytes(xTime(State[index, col]) ^ result[0]);
                if (Constants.ColmnsMixArray[row, index] == 0x3)
                    result = BitConverter.GetBytes((xTime(State[index, col]) ^ State[index, col]) ^ result[0]);
            }
            //result = BitConverter.GetBytes(xTime(0xd4) ^ (xTime(0xbf) ^ 0xbf) ^ 0x5d ^ 0x30);
            return result[0];
        }

        private byte subByte(byte a)
        {
            return Constants.Sbox[(a & 0xf0) >> 4, (a & 0x0f)];
        }

        private void shiftRow(int shiftNumber)
        {
            byte[] result = new byte[4];
            byte tmp;

            for (int index = 0; index < 4; index++)
            {
                result[index] = state[shiftNumber, index];
            }

            for (int index = 0; index < shiftNumber; index++)
            {
                tmp = state[shiftNumber, 0];
                state[shiftNumber, 0] = state[shiftNumber, 1];
                state[shiftNumber, 1] = state[shiftNumber, 2];
                state[shiftNumber, 2] = state[shiftNumber, 3];
                state[shiftNumber, 3] = tmp;
            }
        }
        #endregion
    }
}
