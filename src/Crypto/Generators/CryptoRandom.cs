using System.Security.Cryptography;
using Crypto.Domain.Interfaces;

namespace Crypto.Generators;

public class CryptoRandom : IRandomGenerator, IDisposable
{
    
    #region Fields
    
    private readonly RandomNumberGenerator _randomGen;
    
    #endregion
    
    #region Constructors

    public CryptoRandom() :
        this(RandomNumberGenerator.Create())
    {
    }
    
    public CryptoRandom(RandomNumberGenerator randomGen)
    {
        _randomGen = randomGen ?? throw new ArgumentNullException(nameof(randomGen));
    }
    
    #endregion
    
    #region IRandomGenerator Implementation
    
    public void NextBytes(byte[] bytes)
    {
        _randomGen.GetBytes(bytes);
    }

    public void NextBytes(byte[] bytes, int start, int len)
    {
        
        if (start < 0)
            throw new ArgumentException("Start offset cannot be negative", nameof(start));
        if (start > bytes.Length - len)
            throw new ArgumentException("Byte array too small for requested offset and length");

        if (bytes.Length == len && start == 0) 
        {
            NextBytes(bytes);
        }
        else 
        {
            byte[] tmp = new byte[len];
            NextBytes(tmp);
            tmp.CopyTo(bytes, start);
        }
    }

    public byte[] GenerateArrayBytes(int length)
    {
        byte[] result = new byte[length];
        _randomGen.GetBytes(result);
        return result;
    }
    
    #endregion
    
    #region IDisposable Implementation
    
    public void Dispose()
    {
        _randomGen.Dispose();
        GC.SuppressFinalize(this);
    }
    
    #endregion
    
}