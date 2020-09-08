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
        private byte[,] State;
        private byte[,] Key;
        private byte[,] KeySchedule;   
        private int rCount { get; set; } 
        public int round { get; set; }
        private Constants.EncryptionMode Mode;

        public int Nr { get; set; }
        public int Nb { get; set; }
        public int Nk { get; set; }
        public byte[,] keySchedule { get { return KeySchedule; } }

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

        public Constants.EncryptionMode mode 
        {
            get { return Mode; }
            set
            {
                Mode = value;
                aesSetup(mode);
            }
        }

        public AES(Constants.EncryptionMode mode)
        {
            aesSetup(mode);
        }

        public byte[,] Encrypt(byte[] input, byte[] cipher_Key, Constants.EncryptionMode aesMode)
        {
            Console.WriteLine();
            Console.WriteLine("CIPHER (ENCRYPT):");
            mode = aesMode;

            for (int i = 0; i < Nk; i++)
            {
                for (int d = 0; d < 4; d++)
                {
                    if(i < 4)
                        state[i, d] = input[Nb*i + d];
                    Key[i, d] = cipher_Key[Nb * i + d];
                }
            }

            printArray(state, "input");

            expandKey();
            printKeySchedule();
            addRoundKey();
            round++;

            //1 - Nr - 1 rounds
            for (; round < Nr; round++)
            {
                printArray(state, "Start");
                subBytes();
                printArray(state, "s_box");
                shiftRows();
                printArray(state, "s_row");
                mixColumns();
                printArray(state, "m_col");
                addRoundKey();
                printKeySchedule();
            }

            //Last round
            printArray(state, "Start");
            subBytes();
            printArray(state, "s_box");
            shiftRows();
            printArray(state, "s_row");
            addRoundKey(); 
            printKeySchedule();
            printArray(state, "output");

            return state;
        }

        public byte[,] decrypt(byte[] input, byte[] cipher_Key, Constants.EncryptionMode aesMode)
        {
            Console.WriteLine();
            Console.WriteLine("CIPHER (DECRYPT):");
            mode = aesMode;

            for (int i = 0; i < Nk; i++)
            {
                for (int d = 0; d < 4; d++)
                {
                    if (i < 4)
                        state[i, d] = input[Nb * i + d];
                    Key[i, d] = cipher_Key[Nb * i + d];
                }
            }

            printArray(state, "input");

            expandKey();
            printKeySchedule();
            addRoundKey();
            round++;

            //1 - Nr - 1 rounds
            for (; round < Nr; round++)
            {
                printArray(state, "Start");
                invSubBytes();
                printArray(state, "s_box");
                invShiftRows();
                printArray(state, "s_row");
                invMixColumns();
                printArray(state, "m_col");
                addRoundKey();
                printKeySchedule();
            }

            //Last round
            printArray(state, "Start");
            invSubBytes();
            printArray(state, "s_box");
            invShiftRows();
            printArray(state, "s_row");
            addRoundKey();
            printKeySchedule();
            printArray(state, "output");

            return state;
        }

        #region helpers for test
        public byte[,] Encrypt(byte[] input, byte[] cipher_Key, Constants.EncryptionMode mode, int rounds)
        {
            aesSetup(mode);

            for (int i = 0; i < 4; i++)
            {
                for (int d = 0; d < 4; d++)
                {
                    state[i, d] = input[4 * i + d];
                    Key[i, d] = cipher_Key[4 * i + d];
                }
            }

            expandKey();
            addRoundKey();
            rCount = 4;

            for (int round = 0; round < rounds-1; round++)
            {
                subBytes();
                shiftRows();
                mixColumns();
                addRoundKey();
            }

            return state;
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
                if (index < Nk)
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
                    temp[0] = keySchedule[index - 1, 0];
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
            for (int i = 0; i < Nb; i++)
            {
                for (int d = 0; d < 4; d++)
                {
                    state[i, d] = subByte(state[i, d]);
                }
            }
        }

        public void mixColumns()
        {
            var tmpState = new byte[Nb, 4];

            for (int row = 0; row < Nb; row++)
            {
                tmpState[row, 0] = BitConverter.GetBytes(xTime(State[row, 0]) ^ (xTime(State[row, 1]) ^ State[row, 1]) ^ State[row, 2] ^ State[row, 3])[0];
                tmpState[row, 1] = BitConverter.GetBytes(xTime(State[row, 1]) ^ (xTime(State[row, 2]) ^ State[row, 2]) ^ State[row, 3] ^ State[row, 0])[0];
                tmpState[row, 2] = BitConverter.GetBytes(xTime(State[row, 2]) ^ (xTime(State[row, 3]) ^ State[row, 3]) ^ State[row, 0] ^ State[row, 1])[0];
                tmpState[row, 3] = BitConverter.GetBytes(xTime(State[row, 3]) ^ (xTime(State[row, 0]) ^ State[row, 0]) ^ State[row, 1] ^ State[row, 2])[0];
            }

            State = tmpState;
        }

        public void shiftRows()
        {
            for (int row = 1; row < 4; row++)
            {
                shiftRow(row);
            }
        }

        public void addRoundKey()
        {
            for (int i = 0; i < 4; i++)
            {
                addRoundKeyBytes(i);
                rCount++;
            }
        }

        public void invSubBytes()
        {
            for (int i = 0; i < Nb; i++)
            {
                for (int d = 0; d < 4; d++)
                {
                    state[i, d] = invSubByte(state[i, d]);
                }
            }
        }

        public void invMixColumns()
        {
            var tmpState = new byte[Nb, 4];

            for (int row = 0; row < Nb; row++)
            {
                tmpState[row, 0] = BitConverter.GetBytes(ffMultiply(0x0e, state[row, 0]) ^ ffMultiply(0x0b, state[row, 1]) ^ ffMultiply(0x0d, state[row, 2]) ^ ffMultiply(0x09, state[row, 3]))[0];
                tmpState[row, 1] = BitConverter.GetBytes(ffMultiply(0x09, state[row, 0]) ^ ffMultiply(0x0e, state[row, 1]) ^ ffMultiply(0x0b, state[row, 2]) ^ ffMultiply(0x0d, state[row, 3]))[0];
                tmpState[row, 2] = BitConverter.GetBytes(ffMultiply(0x0d, state[row, 0]) ^ ffMultiply(0x09, state[row, 1]) ^ ffMultiply(0x0e, state[row, 2]) ^ ffMultiply(0x0b, state[row, 3]))[0];
                tmpState[row, 3] = BitConverter.GetBytes(ffMultiply(0x0b, state[row, 0]) ^ ffMultiply(0x0d, state[row, 1]) ^ ffMultiply(0x09, state[row, 2]) ^ ffMultiply(0x0e, state[row, 3]))[0];
            }

            State = tmpState;
        }

        public void invShiftRows()
        {
            for (int row = 1; row < 4; row++)
            {
                invShiftRow(row);
            }
        }
        #endregion

        #region Helper Private

        private void aesSetup(Constants.EncryptionMode mode)
        {
            switch (mode)
            {
                case Constants.EncryptionMode.AES128:
                    Nb = 4;
                    Nk = 4;
                    Nr = 10;
                    break;
                case Constants.EncryptionMode.AES192:
                    Nb = 4;
                    Nk = 6;
                    Nr = 12;
                    break;
                case Constants.EncryptionMode.AES256:
                    Nb = 4;
                    Nk = 8;
                    Nr = 14;
                    break;
                default:
                    break;
            }
            rCount = 0;
            round = 0;
            State = new byte[Nb, 4];
            Key = new byte[Nk, 4];
            KeySchedule = new byte[(Nb*(Nr+1)), 4];
        }

        private uint getKey(int index)
        {
            byte[] tmp = new byte[4];
            tmp[3] = key[index, 0];
            tmp[2] = key[index, 1];
            tmp[1] = key[index, 2];
            tmp[0] = key[index, 3];

            return BitConverter.ToUInt32(tmp, 0);
        }

        private byte subByte(byte a)
        {
            return Constants.Sbox[(a & 0xf0) >> 4, (a & 0x0f)];
        }

        private byte invSubByte(byte a)
        {
            return Constants.InvSbox[(a & 0xf0) >> 4, (a & 0x0f)];
        }

        private void shiftRow(int shiftNumber)
        {
            byte tmp;

            for (int index = 0; index < shiftNumber; index++)
            {
                tmp = state[0, shiftNumber];
                state[0, shiftNumber] = state[1, shiftNumber];
                state[1, shiftNumber] = state[2, shiftNumber];
                state[2, shiftNumber] = state[3, shiftNumber];
                state[3, shiftNumber] = tmp;
            }
        }

        private void invShiftRow(int shiftNumber)
        {
            byte tmp;

            for (int index = 0; index < shiftNumber; index++)
            {
                tmp = state[3, shiftNumber];
                state[3, shiftNumber] = state[2, shiftNumber];
                state[2, shiftNumber] = state[1, shiftNumber];
                state[1, shiftNumber] = state[0, shiftNumber];
                state[0, shiftNumber] = tmp;
            }
        }

        private void addRoundKeyBytes(int col)
        {
            byte[] tmpKey = new byte[4];
            tmpKey[0] = KeySchedule[rCount, 0];
            tmpKey[1] = KeySchedule[rCount, 1];
            tmpKey[2] = KeySchedule[rCount, 2];
            tmpKey[3] = KeySchedule[rCount, 3];

            for (int i = 0; i < 4; i++)
            {
                state[col, i] = BitConverter.GetBytes(state[col, i] ^ tmpKey[i])[0];
            }
        }

        private void printArray(byte[,] data, string state)
        {
            Console.Write("round[{0}].{1}         ", round, state);
            for (int i = 0; i < 4; i++)
            {
                for (int d = 0; d < 4; d++)
                {
                    Console.Write("{0}", data[i, d].ToString("X2"));
                }
            }
            Console.WriteLine();
        }

        private void printKeySchedule()
        {
            Console.Write("round[{0}].{1}         ", round, "k_sch");
            for (int i = round*4; i < round*4+4; i++)
            {
                for (int d = 0; d < 4; d++)
                {
                    Console.Write("{0}", KeySchedule[i, d].ToString("X2"));
                }
            }
            Console.WriteLine();
        }
        #endregion
    }
}
