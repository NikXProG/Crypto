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
        
        if (keySize != 128 && keySize != 192 && keySize != 256)
        {
            throw new ArgumentException("DEAL key must be 128, 192 or 256 bits long.");
        }
    
        _keySize = keySize / 8;
        
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