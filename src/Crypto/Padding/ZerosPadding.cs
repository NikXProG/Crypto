using Crypto.Domain.Interfaces;

namespace Crypto.Padding;

public class ZerosPadding : IBlockCipherPadding
{
    public int AddPadding(byte[] input, int inOff)
    {
        int added = input.Length - inOff;

        while (inOff < input.Length)
        {
            input[inOff++] = 0x00;
        }

        return added;
    }

    public int PadCount(byte[] input)
    {
        int count = 0, still00Mask = -1;
        int i = input.Length;
        while (--i >= 0)
        {
            int next = input[i];
            int match00Mask = ((next ^ 0x00) - 1) >> 31;
            still00Mask &= match00Mask;
            count -= still00Mask;
        }
        return count;
    }
    
}