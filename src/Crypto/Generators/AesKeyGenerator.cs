using Crypto.Domain.Interfaces;
using Crypto.Domain.Parameters;

namespace Crypto.Generators;

public class AesKeyGenerator : ISymmetricKeyGenerator
{
    
    #region Fields
    
    private readonly int _keySize;
    
    private readonly IRandomGenerator _randomGen;

    #endregion
    
    #region Constructors
    
    public AesKeyGenerator(IRandomGenerator randomGen, int keySize)
    {
        _randomGen = randomGen ?? throw new ArgumentNullException(nameof(randomGen));
        _keySize = keySize;
    }
    
    #endregion
    
    #region Properties
    
    public int KeySize => _keySize;
    
    public IRandomGenerator RandomGen => _randomGen;

    #endregion
    
    #region Methods
    
    public byte[] GenerateIV()
    {
        return _randomGen.GenerateArrayBytes(16);
    }

    public SymmetricKey GenerateKey()
    {
        return new SymmetricKey(_randomGen.GenerateArrayBytes(_keySize / 8));
    }
    
    #endregion
    
}