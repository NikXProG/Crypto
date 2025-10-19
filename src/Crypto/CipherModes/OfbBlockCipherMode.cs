using Crypto.Domain.Interfaces;
using Crypto.Domain.Parameters;
using Crypto.Utils;

namespace Crypto.CipherModes;

public class OfbBlockCipherMode　: IBlockCipherMode
{
    
    #region Fields
    
    private byte[] _iv, _ofbV, _ofbOutV;
   
    private bool _ivInitialized;
    
    private readonly int _blockSize;
    private readonly IBlockCipher _cipherEngine;
    
    #endregion
    
    #region Constructors
    
    public OfbBlockCipherMode(IBlockCipher cipher, byte[]? iv = null)
    {
        
        _cipherEngine = cipher ?? throw new ArgumentNullException(nameof(cipher));

        _blockSize = _cipherEngine.BlockSizeInBytes;
    
        _iv = new byte[_blockSize];
        
        if (iv != null)
        {
            if (iv.Length != _blockSize)
                throw new ArgumentException($"IV must be exactly {_blockSize} bytes", nameof(iv));
        
            iv.CopyTo(_iv, 0);
            
            _ivInitialized = true;
        }
        
        _ofbV = new byte[_blockSize];
        _ofbOutV = new byte[_blockSize];
        
    }
    
    #endregion
    
    #region Properties
    
    public IBlockCipher CipherEngine => _cipherEngine;
        
    public bool IsPartialBlockOkay => false;
    
    public int BlockSizeInBytes => _cipherEngine.BlockSizeInBytes;
    
    #endregion
    
    #region Methods
    
    public void Setup(bool encrypting, ICryptoParams cryptoParams)
    {
        
        if (cryptoParams is IVWithParams ivParam)
        {
            if (ivParam.IVLength != _blockSize)
                throw new ArgumentException("initialisation vector must be the same length as block size");

            ivParam.WriteIVTo(_iv, 0, _blockSize);
            
            _ivInitialized = true;
            
            cryptoParams = ivParam.InnerParameters;
        }
        else
        {
            if (!_ivInitialized)
            {
                throw new InvalidOperationException(
                    "IV is not initialized. Provide IV either through constructor or IVWithParams in Setup method.");
            }
        }
      
        
        Reset();
        
        _cipherEngine.Setup(true, cryptoParams);
    }
    
    public int ProcessBlock(byte[] inBuf, int inOff, byte[] outBuf, int outOff)
    {
        return ProcessBlock(inBuf.AsSpan(inOff), outBuf.AsSpan(outOff));
    }
    
    public int ProcessBlock(ReadOnlySpan<byte> input, Span<byte> output)
    {
        Guard.ValidLength(input, _blockSize, "input buffer too short");
        Guard.ValidLength(output, _blockSize, "output buffer too short");

        _cipherEngine.ProcessBlock(_ofbV, _ofbOutV);
       
        for (int i = 0; i < _blockSize; i++)
        {
            output[i] = (byte)(_ofbOutV[i] ^ input[i]);
        }
        
        Array.Copy(_ofbV, _blockSize, _ofbV, 0, _ofbV.Length - _blockSize);
        Array.Copy(_ofbOutV, 0, _ofbV, _ofbV.Length - _blockSize, _blockSize);
        
        return _blockSize;
    }
    
    public void Reset()
    {
        Array.Copy(_iv, 0, _ofbV, 0, _iv.Length);
    }
    
    #endregion
    
}