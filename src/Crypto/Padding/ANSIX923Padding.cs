using Crypto.Domain.Interfaces;

namespace Crypto.Padding;

public class ANSIX923Padding : IBlockCipherPadding
{
    public int AddPadding(byte[] input, int inOff)
    {
        throw new NotImplementedException();
    }

    public int PadCount(byte[] input)
    {
        throw new NotImplementedException();
    }
    
}