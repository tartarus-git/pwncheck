using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace pwncheck
{
    class Hash160
    {
        public uint H0;
        public uint H1;
        public uint H2;
        public uint H3;
        public uint H4;

        public Hash160(uint H0, uint H1, uint H2, uint H3, uint H4)
        {
            this.H0 = H0;
            this.H1 = H1;
            this.H2 = H2;
            this.H3 = H3;
            this.H4 = H4;
        }

        char NibbleToHex(byte Value)
        {
            if (Value < 10) { return (char)(0x30 + Value); }
            return (char)(0x37 + Value);
        }

        const uint NIBBLE_MASK = 0b00000000000000000000000000001111;

        unsafe void UIntToHex(uint Value, string CompleteHash, int Index)
        {
            fixed (char* ptr = CompleteHash)
            {
                ptr[Index + 7] = NibbleToHex((byte)(Value & NIBBLE_MASK));
                for (int i = Index + 6; i > Index; i--) { ptr[i] = NibbleToHex((byte)((Value >> 4 * (7 - (i - Index))) & NIBBLE_MASK)); }
                ptr[Index] = NibbleToHex((byte)((Value >> 4 * 7)));
            }
        }

        public string ToHex()
        {
            string Result = "        " + "        " + "        " + "        " + "        ";
            UIntToHex(H0, Result, 0);
            UIntToHex(H1, Result, 8);
            UIntToHex(H2, Result, 16);
            UIntToHex(H3, Result, 24);
            UIntToHex(H4, Result, 32);
            return Result;
        }
    }
}