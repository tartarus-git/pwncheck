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

        const byte LEFT_NIBBLE = 0b11110000;
        const byte RIGHT_NIBBLE = 0b00001111;

        // This modifies the CompleteHash argument.
        unsafe void UIntToHex(uint Value, string CompleteHash, int Index)
        {
            fixed (char* ptr = CompleteHash)
            {
                byte* ValuePtr = (byte*)&Value;
                for (byte* EndValuePtr = ValuePtr + 3; EndValuePtr >= ValuePtr; EndValuePtr--, Index += 2)
                {
                    // Individual bytes don't have endianness because it doesn't make any sense. Bitshifts are abstract, not to the metal.
                    // Think about this: Bitshifting to the left always multiplies by 2.
                    ptr[Index] = NibbleToHex((byte)((*EndValuePtr & LEFT_NIBBLE) >> 4));
                    ptr[Index + 1] = NibbleToHex((byte)(*EndValuePtr & RIGHT_NIBBLE));
                }
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