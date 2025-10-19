using Crypto.Domain.Interfaces;
using Crypto.Domain.Parameters;
using Crypto.Helpers;
using Crypto.Parameters;
using Crypto.Utils;

namespace Crypto.CipherModes;

public class CbcBlockCipherMode : IBlockCipherMode
{

    #region Fields
    
    private byte[] _iv, _cbcV, _cbcNextV;
    private bool _encrypting;
    private bool _ivInitialized;
    
    private readonly int _blockSize;
    private readonly IBlockCipher _cipherEngine;
    
    #endregion
    
    #region Constructors
    
    public CbcBlockCipherMode(IBlockCipher cipher, byte[]? iv = null)
    {
   
        _cipherEngine = cipher ?? throw new ArgumentNullException(nameof(cipher));
        
        
        _blockSize = cipher.BlockSizeInBytes;
        
        _iv = new byte[_blockSize];
        
        if (iv != null)
        {
            if (iv.Length != _blockSize)
                throw new ArgumentException($"IV must be exactly {_blockSize} bytes", nameof(iv));
        
            iv.CopyTo(_iv, 0);
            
            _ivInitialized = true;
        }
        
        _cbcV = new byte[_blockSize];
        _cbcNextV = new byte[_blockSize];
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
        
        _encrypting = encrypting;
        
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
        
        _cipherEngine.Setup(encrypting, cryptoParams);
    }
    
    public int ProcessBlock(byte[] inBuf, int inOff, byte[] outBuf, int outOff)
    {
        return _encrypting
            ? Encrypt(inBuf.AsSpan(inOff), outBuf.AsSpan(outOff))
            : Decrypt(inBuf.AsSpan(inOff), outBuf.AsSpan(outOff));
    }
    
    public int ProcessBlock(ReadOnlySpan<byte> input, Span<byte> output)
    {
        return _encrypting
            ? Encrypt(input, output)
            : Decrypt(input, output);
    }

    private int Encrypt(ReadOnlySpan<byte> input, Span<byte> output)
    {
        Guard.ValidLength(input, _blockSize, "input buffer too short");
        Guard.ValidLength(output, _blockSize, "output buffer too short");
        
        for (int i = 0; i < _blockSize; i++)
        {
            _cbcV[i] ^= input[i];
        }

        int length = _cipherEngine.ProcessBlock(_cbcV, output);

        output[.._blockSize].CopyTo(_cbcV);

        return length;
    }

    private int Decrypt(ReadOnlySpan<byte> input, Span<byte> output)
    {
        Guard.ValidLength(input, _blockSize, "input buffer too short");
        Guard.ValidLength(output, _blockSize, "output buffer too short");
        
        input[.._blockSize].CopyTo(_cbcNextV);

        int length = _cipherEngine.ProcessBlock(input, output);

        for (int i = 0; i < _blockSize; i++)
        {
            output[i] ^= _cbcV[i];
        }

        (_cbcV, _cbcNextV) = (_cbcNextV, _cbcV);
        
        return length;
        
    }

    public void Reset()
    {
        Array.Copy(_iv, 0, _cbcV, 0, _iv.Length);
        Array.Clear(_cbcNextV, 0, _cbcNextV.Length);
    }
    
    #endregion
    
}