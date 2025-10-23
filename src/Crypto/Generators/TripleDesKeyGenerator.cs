using Crypto.Domain.Interfaces;
using Crypto.Domain.Parameters;
using Crypto.Parameters;

namespace Crypto.Generators;

public class TripleDesKeyGenerator : ISymmetricKeyGenerator
{
        
    #region Fields

    private readonly IRandomGenerator _randomGen;
    private readonly int _keySize;
    
    #endregion
    
    #region Constructors

    public TripleDesKeyGenerator(IRandomGenerator randomGen, int keySize)
    {
        _randomGen = randomGen ??  throw new ArgumentNullException(nameof(randomGen));
        _keySize = CalculateKeySize(keySize);
    }
    
    #endregion
    
    #region Properties

    public IRandomGenerator RandomGen => _randomGen;

    public int KeySize => _keySize;

    #endregion
   
    #region Methods
    
    public SymmetricKey GenerateKey()
    {
        byte[] key;
        
        do
        {
            key = new byte[_keySize];
            _randomGen.NextBytes(key);
        } 
        while (TripleDesWeakKeys.IsWeakKey(key) || !TripleDesWeakKeys.IsTripleKey(key));
        
        return new SymmetricKey(key);
    }

    public byte[] GenerateIV()
    {
        return _randomGen.GenerateArrayBytes(8);
    }
    
    private static int CalculateKeySize(int keySizeInBits)
    {
        int strengthInBytes = (keySizeInBits + 7) / 8;

        return strengthInBytes switch
        {
            0 or 21 => 24,                    // 168-bit -> 192-bit (24 bytes)
            14 => 16,                         // 112-bit -> 128-bit (16 bytes)
            16 or 24 => strengthInBytes,      // Valid sizes
            _ => throw new ArgumentException(
                $"Triple DES key must be 128 or 192 bits long. Requested: {keySizeInBits} bits")
        };
    }
    
    #endregion

}