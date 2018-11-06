using System;
using System.Collections.Generic;
using System.Text;

namespace EncryctionDES
{
    class DES
    {
        private int[] StartingReshuffle =
        {
            58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
            62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
            57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
            61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7
        };

        private int[] KeyReshuffle = {
            57,  49,  41,  33,  25,  17,  9,   1,   58,  50,  42,  34,  26,  18,
            10, 2,   59,  51,  43,  35,  27,  19,  11,  3,   60,  52,  44,  36,
            63,  55,  47,  39,  31,  23,  15,  7,   62,  54,  46,  38,  30,  22,
            14,  6,   61,  53,  45,  37,  29,  21,  13,  5,   28,  20,  12,  4
        };

        private int[] ForEFunction =
        {
            32, 1, 2, 3, 4, 5,
            4, 5, 6, 7, 8, 9,
            8, 9, 10, 11, 12, 13,
            12, 13, 14, 15, 16, 17,
            16, 17, 18, 19, 20, 21,
            20, 21, 22, 23, 24, 25,
            24, 25, 26, 27, 28, 29,
            28, 29, 30, 31, 32,1
        };

        private int[] ForKi =
        {
            14,  17,  11,  24,  1 ,  5 ,  3 ,  28 , 15 , 6  , 21 , 10 , 23 , 19 , 12,  4,
            26,  8,  16,  7,   27,  20,  13,  2,   41,  52,  31,  37,  47,  55,  30,  40,
            51,  45,  33,  48,  44,  49,  39,  56,  34,  53,  46,  42,  50,  36,  29,  32
        };

        #region Tables S

        private int[,] S1 =

        {
            { 14,4,   13,  1,   2,   15,  11,  8,  3,   10,  6 ,  12,  5,   9,   0,   7 },
            { 0,   15,  7,   4,   14  ,2   ,13  ,1   ,10  ,6   ,12  ,11  ,9   ,5   ,3   ,8 },
            { 4   ,1   ,14  ,8   ,13  ,6   ,2   ,11  ,15  ,12  ,9   ,7   ,3   ,10  ,5   ,0 },
            { 15  ,12  ,8   ,2   ,4   ,9   ,1   ,7   ,5   ,11  ,3   ,14  ,10  ,0   ,6   ,13}
        };

        private int[,] S2 =
        {
            { 15,  1   8   14  6   11  3   4   9   7   2   13  12  0   5   10 }
            { 3,  13  4   7   15  2   8   14  12  0   1   10  6   9   11  5 }
            {0,  14  7   11  10  4   13  1   5   8   12  6   9   3   2   15}
            {13  8   10  1   3   15  4   2   11  6   7   12  0   5   14  9}
        };


        #endregion;


        private const int BlockSize = 64;
        private const int CharSize = 8;
        private const int KeySize = 56;
        private const int EConst = 48;

        private string[] Blocks;

        private string str; // шифруемый текст
        private string key; // ключ

        public DES(string str, string key)
        {
            this.str = str;
            this.key = key;

            CompleteString();
            CorrectKey();
            DivideTextIntoBlocks();

            key = StringToBinaryFormat(key);
            KeyReshuffleFunc(key.ToCharArray());
        }

        // Дополняем строку * до кратности размеру блока (64)
        private void CompleteString()
        {
            while (str.Length * CharSize % BlockSize != 0)
            {
                str += '*';
            }
        }

        // Разбиваем строку на блоки по 64 бита

        private void DivideTextIntoBlocks()
        {
            Blocks = new string[str.Length * CharSize / BlockSize];

            int blockLength = str.Length / Blocks.Length;

            for (int i = 0; i < Blocks.Length; i++)
            {
                Blocks[i] = str.Substring(i * blockLength, blockLength);
                Blocks[i] = StringToBinaryFormat(Blocks[i]);
            }
        }

        // Переводит строку в двоичный формат
        private string StringToBinaryFormat(string str)
        {
            string binaryString = "";

            for (int i = 0; i < str.Length; i++)
            {
                string binary = Convert.ToString(str[i], 2); // Переводим в двоичный формат каждый символ строки

                // Дополняем незначащими нулями до длины байта
                while (binary.Length < CharSize)
                {
                    binary = "0" + binary;
                }
                binaryString += binary;
            }

            return binaryString;
        }

        // Разбивает двоичную строку на блоки
        private void DivideBinaryTextIntoBlocks(string binaryText) {
            Blocks = new string[binaryText.Length / BlockSize];
            int BlockLength = binaryText.Length / Blocks.Length;

            for (int i = 0; i < Blocks.Length; i++)
            {
                Blocks[i] = binaryText.Substring(i * BlockLength, BlockLength);
            }
        }

        // Преобразуем ключ до нужной длины
        private void CorrectKey()
        {
            if (key.Length > KeySize)
            {
                key = key.Substring(0, KeySize);
            }
            else
            {
                while (key.Length < KeySize)
                {
                    key += "0";
                }
            }
        }

        // Меняем биты в блоке по схеме (см. вики)
        // получаем IP(T)
        public char[,] FirsStep()
        {
            char[,] changedBlocks = new char [Blocks.Length, BlockSize]; // Преобразованный блок

            // Проходим по каждому блоку и меняем местами биты по схеме
            for (int j = 0; j < Blocks.Length; j++)
            {
                for (int i = 0; i < BlockSize; i++)
                {
                    changedBlocks[j, i] = Blocks[j][StartingReshuffle[i] - 1];
                }
            }

            return changedBlocks;
        }

        private void FeistelFunction(char [] R, string k)
        {
            char[] E = EFunction(R);
            char[] B;

            // Побитовое сложение ключа и преобразованной правой части
            int intE = Convert.ToInt32(E.ToString());
            int intK = Convert.ToInt32(k.ToString());
            int intB = intE ^ intK;
        }
        
        // E-функция, дополняет R до 48 битов
        // Получаем ER
        private char[] EFunction(char [] R)
        {
            char[] ER = new char [EConst];

            for(int j = 0; j < EConst; j++)
            {
                ER[j] = R[ForEFunction[j] - 1];
            }

            return ER;
        }

        // Первичная перестановка ключа
        private char [] KeyReshuffleFunc(char [] K)
        {
            char[] changedKey = new char[BlockSize];
            char[] replacedKey = new char[KeySize];

            int c = 0;
            int j = 0;
            // Дополняем ключ до 64-битного
            for (int i = 0; i < BlockSize; i++)
            {
                if (i % 7 == 0 && i !=0 )
                {
                    if (c % 2 == 0)
                    {
                        changedKey[i] = '1';
                    }
                    else
                    {
                        changedKey[i] = '0';
                    }
                    c = 0;
                    continue;
                }
                c += (int)Char.GetNumericValue(K[j]);
                changedKey[i] = K[j];
                j++;
            }

            //Выполняем перестановку согласно схеме
            for (int i = 0; i < KeySize; i++)
            {
                replacedKey[i] = changedKey[KeyReshuffle[i] - 1];
            }

            return replacedKey;
        }
        

        // Получаем ключ для каждого шага
        private char[] getKi (char [] previousK, byte step)
        {
            char[] Ki = new char[48];

            // Делим ключ на равные части
            char[] C0 = previousK.ToString().Substring(0, 28).ToCharArray();
            char[] D0 = previousK.ToString().Substring(29, 56).ToCharArray();

            // Циклический сдвиг влево в зависимости от условия step
            char[] Ci = LeftShift(C0);
            char[] Di = LeftShift(D0);

            if (step != 1 && step != 2 && step != 9 && step != 16)
            {
                Ci = LeftShift(Ci);
                Di = LeftShift(Di);
            }

            // Объединяем Ci и Di
            char[] CiDi = new char[56];
            Ci.CopyTo(CiDi, 0);
            Di.CopyTo(CiDi, Ci.Length);

            // Заполняем Ki
            for (int i = 0; i<48; i++)
            {
                Ki[i] = CiDi[ForKi[i]-1];
            }

            return Ki;
        }

        #region Сдвиг влево
        // Циклический сдвиг влево
        private char[] LeftShift(char[] array)
        {
            char temp = array[0];
            for (int i = 27; i>0; i--)
            {
                array[i-1] = array[i];
            }
            array[27] = temp;

            return array;
        }

        #endregion
    }
}
