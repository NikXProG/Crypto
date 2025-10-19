using Crypto.Domain.Interfaces;

namespace Crypto.Padding;

public class ISO10126Padding : IBlockCipherPadding
{
    
    #region Fields
    
    private readonly IRandomGenerator _randomGen;

    #endregion
    
    #region Constructors
    
    public ISO10126Padding(IRandomGenerator randomGen)
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
        input[input.Length - 1] = (byte)count;

        return count;
    }

    public int PadCount(byte[] input)
    {
        throw new NotImplementedException();
    }
    
    #endregion
    
}