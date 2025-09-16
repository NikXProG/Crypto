using Crypto.Core.Interfaces;

namespace Crypto.Padding;

public class ZerosPadding : IBlockCipherPadding
{
    
    public int ApplyPadding(ReadOnlySpan<byte> block, Span<byte> destination, int paddingSizeInBytes)
    {
        throw new NotImplementedException();
    }

    public int CalculatePaddedLength(int plaintextLength, int paddingSizeInBytes)
    {
        throw new NotImplementedException();
    }

    public bool IsAutoDepaddingSupported()
    {
        throw new NotImplementedException();
    }

    public int ValidateAndRemovePadding(ReadOnlySpan<byte> block, int blockSize)
    {
        throw new NotImplementedException();
    }
    
}