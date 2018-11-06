using System;

namespace EncryctionDES
{
    class Program
    {
        

        static void Main(string[] args)
        {

            string text = "abcdefghi";
            string key = "1234567";

            DES encryptor = new DES(text, key);

            encryptor.FirsStep();
            Console.ReadKey();
        }
    }
}
