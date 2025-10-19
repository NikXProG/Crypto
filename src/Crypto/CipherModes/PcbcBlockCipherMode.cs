using Crypto.Domain.Interfaces;
using Crypto.Domain.Parameters;
using Crypto.Utils;

namespace Crypto.CipherModes;

public class PcbcBlockCipherMode : IBlockCipherMode
{
    
    #region Fields
    
    private byte[] _iv, _pcbcV, _pcbcNextV;
    private bool _encrypting;
    private bool _ivInitialized;
    
    private readonly int _blockSize;
    private readonly IBlockCipher _cipherEngine;
    
    #endregion
    
    #region Constructors
    
    public PcbcBlockCipherMode(IBlockCipher cipher, byte[]? iv = null)
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
        
        _pcbcV = new byte[_blockSize];
        _pcbcNextV = new byte[_blockSize];
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
            _pcbcV[i] ^= input[i];
        }

        int length = _cipherEngine.ProcessBlock(_pcbcV, output);
        
        for (int i = 0; i < _blockSize; i++)
        {
            _pcbcV[i] = (byte)(input[i] ^ output[i]);
        }

        return length;
    }

    private int Decrypt(ReadOnlySpan<byte> input, Span<byte> output)
    {
        Guard.ValidLength(input, _blockSize, "input buffer too short");
        Guard.ValidLength(output, _blockSize, "output buffer too short");
        
        input[.._blockSize].CopyTo(_pcbcNextV);
        
        int length = _cipherEngine.ProcessBlock(input, output);
        
        for (int i = 0; i < _blockSize; i++)
        {
            output[i] ^= _pcbcV[i];
        }
        
        for (int i = 0; i < _blockSize; i++)
        {
            _pcbcV[i] = (byte)(_pcbcNextV[i] ^ output[i]);
        }
        
        return length;
        
    }

    public void Reset()
    {
        Array.Copy(_iv, 0, _pcbcV, 0, _iv.Length);
        Array.Clear(_pcbcNextV, 0, _pcbcNextV.Length);
    }
    
    #endregion
    
    
}