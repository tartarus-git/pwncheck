using System.Text;

namespace pwncheck
{
    static class SHA1
    {
        public static Hash160 Hash(byte[] Message)
        {
            // Use nothing up my sleeve numbers as starting point.
            Hash160 Hash = new Hash160(0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0);

            // Pad message while accounting for 64-bit message length so it is divisable by 512.
            int NewMessageLength = Message.Length + 1 + 8;
            byte[] PaddedMessage = new byte[NewMessageLength + 64 - NewMessageLength % 64];
            // Add a high bit to the end. The zeros will count towards the padding anyway.
            PaddedMessage[Message.Length] = 0b10000000;
            // Copy Message to PaddedMessage.
            Message.CopyTo(PaddedMessage, 0);

            // Add original message length to end as a big-endian unsigned 64-bit integer.
            unsafe
            {
                ulong BitAmount = (ulong)(Message.Length * 8);
                byte* ptr = (byte*)&BitAmount;
                int j = 7;
                for (int i = 8; i > 0; i--, j--)
                {
                    PaddedMessage[PaddedMessage.Length - i] = *(ptr + j);
                }
            }

            // Go through the message, one 512-bit chunk at a time.
            int ni = 64;
            for (int i = 0; i < PaddedMessage.Length; i = ni, ni += 64)
            {
                // Create 16 words containing 4 characters each.
                uint[] Words = new uint[80];
                int WordIndex = 0;
                for (int j = i; j < ni; j += 4, WordIndex++) { Words[WordIndex] = ((uint)PaddedMessage[j] << 24) | 
                        ((uint)PaddedMessage[j + 1] << 16) | ((uint)PaddedMessage[j + 2] << 8) | PaddedMessage[j + 3]; }

                // Extend 16 words into 80.
                for (int j = 16; j < 80; j++)
                {
                    Words[j] = Words[j - 3] ^ Words[j - 8] ^ Words[j - 14] ^ Words[j - 16];
                    Words[j] = (Words[j] << 1) | (Words[j] >> (32 - 1));
                }

                // Initialize hash value for this chunk.
                uint a = Hash.H0;
                uint b = Hash.H1;
                uint c = Hash.H2;
                uint d = Hash.H3;
                uint e = Hash.H4;

                // Intermediate values.
                uint f;
                uint k;

                void FinishWord(int Index)
                {
                    uint temp = ((a << 5) | (a >> (32 - 5))) + f + e + k + Words[Index];
                    e = d;
                    d = c;
                    c = (b << 30) | (b >> (32 - 30));
                    b = a;
                    a = temp;
                }

                // Containerized main loop.
                for (int j = 0; j < 20; j++)
                {
                    f = (b & c) | ((~b) & d);
                    k = 0x5A827999;
                    FinishWord(j);
                }
                for (int j = 20; j < 40; j++)
                {
                    f = b ^ c ^ d;
                    k = 0x6ED9EBA1;
                    FinishWord(j);
                }
                for (int j = 40; j < 60; j++)
                {
                    f = (b & c) | (b & d) | (c & d);
                    k = 0x8F1BBCDC;
                    FinishWord(j);
                }
                for (int j = 60; j < 80; j++)
                {
                    f = b ^ c ^ d;
                    k = 0xCA62C1D6;
                    FinishWord(j);
                }

                // Add this chunk's hash to the result so far.
                Hash.H0 += a;
                Hash.H1 += b;
                Hash.H2 += c;
                Hash.H3 += d;
                Hash.H4 += e;
            }
            // Return the final hash as a Hash160.
            return Hash;
        }
    }
}