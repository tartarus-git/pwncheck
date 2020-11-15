using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace pwncheck
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine(SHA1.Hash("a").ToHex());
            Console.ReadKey();
        }
    }
}
