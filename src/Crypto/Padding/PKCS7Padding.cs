using Crypto.Domain.Interfaces;

namespace Crypto.Padding;

public class PKCS7Padding : IBlockCipherPadding
{
    public int AddPadding(byte[] input, int inOff)
    {
        int count = input.Length - inOff;
        byte padValue = (byte)count;

        while (inOff < input.Length)
        {
            input[inOff++] = padValue;
        }

        return count;
    }
    

    public int PadCount(byte[] input)
    {
        byte padValue = input[^1];
        int count = padValue;
        int position = input.Length - count;

        int failed = (position | (count - 1)) >> 31;
        for (int i = 0; i < input.Length; ++i)
        {
            failed |= (input[i] ^ padValue) & ~((i - position) >> 31);
        }
        if (failed != 0)
            throw new InvalidOperationException("pad block corrupted");

        return count;
    }
}