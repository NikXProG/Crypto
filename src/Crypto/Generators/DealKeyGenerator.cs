using Crypto.Domain.Interfaces;
using Crypto.Domain.Parameters;

namespace Crypto.Generators;

public class DealKeyGenerator : ISymmetricKeyGenerator
{
            
    #region Fields

    private readonly IRandomGenerator _randomGen;
    private readonly int _keySize;
    
    #endregion
    
    #region Constructors

    public DealKeyGenerator(IRandomGenerator randomGen, int keySize)
    {
        _randomGen = randomGen ??  throw new ArgumentNullException(nameof(randomGen));
        _keySize = (keySize + 7) / 8;
        
        if (_keySize != 16 && _keySize != 24 && _keySize != 32)
        {
            throw new ArgumentException("DEAL key must be 128, 192 or 256 bits long.");
        }
    }
    
    #endregion
    
    #region Properties

    public IRandomGenerator RandomGen => _randomGen;

    public int KeySize => _keySize;

    #endregion
   
    #region Methods
    
    public SymmetricKey GenerateKey()
    {
        byte[] key = new byte[_keySize];
        _randomGen.NextBytes(key);
        return new SymmetricKey(key);
    }

    public byte[] GenerateIV()
    {
        return _randomGen.GenerateArrayBytes(16);
    }
    
    #endregion
    
}