using Crypto.Domain.Interfaces;
using Crypto.Domain.Parameters;
using Crypto.Utils;

namespace Crypto.CipherModes;

public class CfbBlockCipherMode : IBlockCipherMode
{
    
    #region Fields
    
    private byte[]	_iv, _cfbV, _cfbOutV;
    private bool _encrypting;
    private bool _ivInitialized;
    
    private readonly int _blockSize;
    private readonly IBlockCipher _cipherEngine;
    
    #endregion

    #region Constructors


    public CfbBlockCipherMode(
        IBlockCipher cipher,
        int feedbackSize,
        byte[]? iv = null)
    {
        if (feedbackSize < 8 || (feedbackSize & 7) != 0)
        {
            throw new ArgumentOutOfRangeException(nameof(feedbackSize),"CFB" + feedbackSize + " not supported");
        }
        
        _cipherEngine = cipher;
        _blockSize = feedbackSize / 8;
        
        int cipherBlockSize = cipher.BlockSizeInBytes;
        
        _iv = new byte[cipherBlockSize];
        
        if (iv != null)
        {
            if (iv.Length != cipherBlockSize)
                throw new ArgumentException($"IV must be exactly {cipherBlockSize} bytes", nameof(iv));
        
            iv.CopyTo(_iv, 0);
            
            _ivInitialized = true;
        }
        
        _cfbV = new byte[cipherBlockSize];
        _cfbOutV = new byte[cipherBlockSize];
        
    }
    
   
    public void Setup(bool encrypting, ICryptoParams cryptoParams)
    {
        _encrypting = encrypting;
        
        if (cryptoParams is IVWithParams ivParam)
        {
            
            if (ivParam.IVLength != _blockSize)
                throw new ArgumentException("initialisation vector must be the same length as block size");

            ivParam.WriteIVTo(_iv, 0, _blockSize);
            
            _ivInitialized = true;
        }
        else
        {
            if (_iv == null)
            {
                throw new InvalidOperationException(
                    "IV is not initialized. Provide IV either through constructor or IVWithParams in Setup method.");
            }
        }
      
      
        
        Reset();
        
        _cipherEngine.Setup(true, cryptoParams);
        
    }

    #endregion

    #region Properties

    public int BlockSizeInBytes => _cipherEngine.BlockSizeInBytes;

    public IBlockCipher CipherEngine => _cipherEngine;

    public bool IsPartialBlockOkay => true;
    
    #endregion
    
    #region Methods

    public int ProcessBlock(byte[] inBuf, int inOff, byte[] outBuf, int outOff)
    {
        return _encrypting
            ? EncryptBlock(inBuf.AsSpan(inOff), outBuf.AsSpan(outOff))
            : DecryptBlock(inBuf.AsSpan(inOff), outBuf.AsSpan(outOff));
    }

    public int ProcessBlock(ReadOnlySpan<byte> input, Span<byte> output)
    {
        return _encrypting
            ? EncryptBlock(input, output)
            : DecryptBlock(input, output);
    }
    
    private int EncryptBlock(ReadOnlySpan<byte> input, Span<byte> output)
    {
        
        Guard.ValidLength(input, _blockSize, "input buffer too short");
        Guard.ValidLength(output, _blockSize, "output buffer too short");

        _cipherEngine.ProcessBlock(_cfbV, _cfbOutV);
        
        // XOR the cfbV with the plaintext producing the ciphertext
        for (int i = 0; i < _blockSize; i++)
        {
            output[i] = (byte)(_cfbOutV[i] ^ input[i]);
        }
      
        Array.Copy(_cfbV, _blockSize, _cfbV, 0, _cfbV.Length - _blockSize);
        output[.._blockSize].CopyTo(_cfbV.AsSpan(_cfbV.Length - _blockSize));
        return _blockSize;
    }
    
    private int DecryptBlock(ReadOnlySpan<byte> input, Span<byte> output)
    {
        Guard.ValidLength(input, _blockSize, "input buffer too short");
        Guard.ValidLength(output, _blockSize, "output buffer too short");

        _cipherEngine.ProcessBlock(_cfbV, 0, _cfbOutV, 0);
      
        Array.Copy(_cfbV, _blockSize, _cfbV, 0, _cfbV.Length - _blockSize);
        input[.._blockSize].CopyTo(_cfbV.AsSpan(_cfbV.Length - _blockSize));
      
        
        // XOR the cfbV with the ciphertext producing the plaintext
        for (int i = 0; i < _blockSize; i++)
        {
            output[i] = (byte)(_cfbOutV[i] ^ input[i]);
        }
        return _blockSize;
    }

    public void Reset()
    {
        Array.Copy(
            _iv, 
            0, 
            _cfbV, 
            0, _iv.Length);
    }
    
    #endregion
    
    
}