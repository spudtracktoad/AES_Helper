using System;
using System.Collections.Generic;
using System.Dynamic;
using System.Linq;
using System.Reflection;
using System.Runtime.Remoting.Messaging;
using System.Text;
using System.Threading.Tasks;

namespace AESEncryption
{
    public class AES
    {
        private byte[,] State = new byte[4, 4];
        private byte[,] Key = new byte[4,4];
        private byte[,] KeySchedule = new byte[44,4];

        public int round { get; set; } = 0;
        public int Nr { get; set; } = 10;
        public int Nb { get; set; } = 4;
        public int Nk { get; set; } = 4;

        public byte[,] keySchedule { get { return KeySchedule; } }

        public byte[,] Encrypt(byte[] input, byte[] cipher_Key, Constants.EncryptionMode mode)
        {
            for (int i = 0; i < 4; i++)
            {
                for (int d = 0; d < 4; d++)
                {
                    state[d, i] = input[4*i + d];
                    Key[d, i] = cipher_Key[4 * i + d];
                }
            }

            expandKey();

            addRoundKey();


            return state;
        }

        #region helpers for test
        public byte[,] key 
        {
            get { return Key; }
            set { Key = value; } 
        }

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

            var tmpWord = BitConverter.GetBytes(word);

            result = BitConverter.ToUInt32(subWord(tmpWord), 0);

            return result;
        }

        public byte[] subWord(byte[] word)
        {
            byte[] tmpBytes = word;

            for (int i = 0; i < 4; i++)
            {
                tmpBytes[i] = subByte(tmpBytes[i]);
            }

            return tmpBytes;
        }

        //public uint rotWord(uint word)
        //{
        //    uint result;

        //    var tmpWord = BitConverter.GetBytes(word);

        //    result = BitConverter.ToUInt32(rotWord(tmpWord), 0);

        //    return result;
        //}

        public byte[] rotWord(byte[] word)
        {
            byte[] tmpBytes = word;
            byte tmpByte;

            tmpByte = tmpBytes[0];
            tmpBytes[0] = tmpBytes[1];
            tmpBytes[1] = tmpBytes[2];
            tmpBytes[2] = tmpBytes[3];
            tmpBytes[3] = tmpByte;

            return tmpBytes;
        }

        public void expandKey(byte[,] keyInput)
        {
            key = keyInput;
            expandKey();
        }


        public void expandKey()
        {
            for (int index = 0; index < (Nb * (Nr + 1)); index++)
            {
                if (index < 4)
                {
                    var tmp = BitConverter.GetBytes(getKey(index));
                    KeySchedule[index, 0] = tmp[3];
                    KeySchedule[index, 1] = tmp[2];
                    KeySchedule[index, 2] = tmp[1];
                    KeySchedule[index, 3] = tmp[0];
                }
                else
                {
                    byte[] temp = new byte[4];
                    temp[0] = keySchedule[index-1, 0];
                    temp[1] = keySchedule[index - 1, 1];
                    temp[2] = keySchedule[index - 1, 2];
                    temp[3] = keySchedule[index - 1, 3];

                    if ((index % Nk) == 0)
                    {
                        var tmp = BitConverter.GetBytes(Constants.Rcon[index / Nk]);
                        temp = subWord(rotWord(temp));
                        for (int i = 0; i < 4; i++)
                        {
                            temp[i] = BitConverter.GetBytes(temp[i] ^ tmp[3-i])[0];
                            temp[i] = BitConverter.GetBytes(temp[i] ^ keySchedule[index-4,i])[0];
                        }
                    }
                    else if (Nk > 6 && index % Nk == 4)
                    {
                        temp = subWord(temp);
                    }
                    for (int i = 0; i < 4; i++)
                    {
                        keySchedule[index,i] = BitConverter.GetBytes(keySchedule[index - Nk,i] ^ temp[i])[0];
                    }
                }
            }
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

        public void addRoundKey()
        {
            for (int i = round; i < round+4; i++)
            {
                addRoundKeyBytes(i);
            }
        }
        #endregion

        #region Helper Private

        private uint getKey(int index)
        {
            byte[] tmp = new byte[4];
            tmp[3] = key[index, 0];
            tmp[2] = key[index, 1];
            tmp[1] = key[index, 2];
            tmp[0] = key[index, 3];

            return BitConverter.ToUInt32(tmp, 0);
        }

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

        private void addRoundKeyBytes(int col)
        {
            byte[] tmpKey = new byte[4];
            tmpKey[0] = KeySchedule[0, col];
            tmpKey[1] = KeySchedule[1, col];
            tmpKey[2] = KeySchedule[2, col];
            tmpKey[3] = KeySchedule[3, col];

            for (int i = 0; i < 4; i++)
            {
                state[i, col%4] = BitConverter.GetBytes(state[i, col%4] ^ tmpKey[i])[0];
            }
        }
        #endregion
    }
}
