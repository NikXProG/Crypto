using Crypto.Domain.Interfaces;

namespace Crypto.Padding;

public class ANSIX923Padding : IBlockCipherPadding
{
    #region Fields
    
    private readonly IRandomGenerator _randomGen;

    #endregion
    
    #region Constructors
    
    public ANSIX923Padding(IRandomGenerator randomGen)
    {
        _randomGen = randomGen ?? throw new ArgumentNullException(nameof(randomGen));
    }
    
    #endregion
    
    #region Methods
    
    public int AddPadding(byte[] input, int inOff)
    {
        int count = input.Length - inOff;
        if (count > 1)
        {
            _randomGen.NextBytes(input, inOff, count - 1);
        }
        input[^1] = (byte)count;
        return count;
    }

    public int PadCount(byte[] input)
    {
        int count = input[^1];
        int position = input.Length - count;

        int failed = (position | (count - 1)) >> 31;
        if (failed != 0)
            throw new InvalidOperationException("pad block corrupted");

        return count;
    }
    
    #endregion
    
}