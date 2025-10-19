using Crypto.Domain.Interfaces;

namespace Crypto.CipherModes;

public class EcbBlockCipherMode : IBlockCipherMode
{
    
    #region Fields
    
    private readonly IBlockCipher _cipherEngine;
    
    #endregion
    
    #region Constructors
    
    public EcbBlockCipherMode(IBlockCipher cipher)
    {
        _cipherEngine = cipher ?? throw new ArgumentNullException(nameof(cipher));
    }
    
    #endregion
    
    #region Properties

    public IBlockCipher CipherEngine => _cipherEngine;
    
    public bool IsPartialBlockOkay => false;
    
    public int BlockSizeInBytes => _cipherEngine.BlockSizeInBytes;
    
    #endregion
    
    #region Methods

    public int ProcessBlock(byte[] inBuf, int inOff, byte[] outBuf, int outOff)
    {
        return _cipherEngine.ProcessBlock(inBuf, inOff, outBuf, outOff);
    }

    public int ProcessBlock(ReadOnlySpan<byte> input, Span<byte> output)
    {
        return _cipherEngine.ProcessBlock(input, output);
    }

    public void Setup(bool encrypting, ICryptoParams key)
    {
        _cipherEngine.Setup(encrypting, key);
    }

    public void Reset()
    {
        // not realize
    }

    #endregion
    
    
    
}