using System.Security.Cryptography;
using Crypto.Domain.Interfaces;
using Crypto.Domain.Parameters;
using Crypto.Parameters;

namespace Crypto.Generators;

public class DesKeyGenerator : ISymmetricKeyGenerator
{
    
    #region Fields

    private readonly IRandomGenerator _randomGen;
    
    #endregion
    
    #region Constructors

    public DesKeyGenerator(IRandomGenerator randomGen)
    {
        _randomGen = randomGen ??  throw new ArgumentNullException(nameof(randomGen));
    }
    
    #endregion
    
    #region Properties

    public IRandomGenerator RandomGen => _randomGen;

    public int KeySize => 64;

    #endregion
   
    #region Methods
    
    public SymmetricKey GenerateKey()
    {
        byte[] key;
        
        do
        {
            key = new byte[8];
            _randomGen.NextBytes(key);
        } 
        while (!DesWeakKeys.IsValidKey(key));
        
        return new SymmetricKey(key);
    }

    public byte[] GenerateIV()
    {
        return _randomGen.GenerateArrayBytes(8);
    }
    
    #endregion
    
}