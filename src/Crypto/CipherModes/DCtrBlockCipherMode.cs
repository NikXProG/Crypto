using Crypto.Domain.Enums;
using Crypto.Domain.Interfaces;
using Crypto.Domain.Parameters;
using Crypto.Utils;

namespace Crypto.CipherModes;

public class DCtrBlockCipherMode : IBlockCipherMode, IStreamCipher
{
    
    #region Fields

    private byte[] _iv, _ofbV, _ofbOutV;
    private bool _ivInitialized;
    private bool _initialized;
    
    private int _byteCount;
    private int _delta = 1;
    
    private readonly CtrCounterMode _ctrCounterMode;
    private readonly int _blockSize;
    private readonly IBlockCipher _cipherEngine;
    
    #endregion
    
    #region Constructors
    
    public DCtrBlockCipherMode(
        IBlockCipher cipher, 
        CtrCounterMode mode = CtrCounterMode.One,
        byte[]? iv = null)
    {
        _cipherEngine = cipher ?? throw new ArgumentNullException(nameof(cipher));
        
        _blockSize = cipher.BlockSizeInBytes;
        
        _iv = new byte[_blockSize];
        
        _ctrCounterMode = mode;
        
        if (iv != null)
        {
            if (iv.Length != _blockSize)
                throw new ArgumentException($"IV must be exactly {_blockSize} bytes", nameof(iv));
        
            iv.CopyTo(_iv, 0);

            
            _delta = _ctrCounterMode switch
            {
                CtrCounterMode.One => 1,
                CtrCounterMode.RandomDelta => GenerateRandomDelta(),
                _ => throw new ArgumentException($"Unknown counter mode: {_ctrCounterMode}")
            };
            
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
        _initialized = true;
        
        
        if (cryptoParams is IVWithParams ivParam)
        {
            
            if (ivParam.IVLength != _blockSize)
                throw new ArgumentException("initialisation vector must be the same length as block size");

            ivParam.WriteIVTo(_iv, 0, _blockSize);
            
            _delta = _ctrCounterMode switch
            {
                CtrCounterMode.One => 1,
                CtrCounterMode.RandomDelta => GenerateRandomDelta(),
                _ => throw new ArgumentException($"Unknown counter mode: {_ctrCounterMode}")
            };

            cryptoParams = ivParam.InnerParameters;
            
            _ivInitialized = true;
        }
        else
        {
            if (!_ivInitialized)
            {
                throw new InvalidOperationException(
                    "IV is not initialized. Provide IV either through constructor or IVWithParams in Setup method.");
            }
        }
        
        _cipherEngine.Setup(true, cryptoParams);
        
        
        Reset();
        
    }
    
    public void ProcessBytes(byte[] input, int inOff, int len, byte[] output, int outOff)
    {
        ProcessBytes(input.AsSpan(inOff, len),
            output.AsSpan(outOff, len));
    }
    
    public void ProcessBytes(ReadOnlySpan<byte> input, Span<byte> output)
    {
        Guard.ValidLength(output, input.Length, "output buffer too short");

        for (int i = 0; i < input.Length; ++i)
        {
            output[i] = CalculateByte(input[i]);
        }
    }
    
    public int ProcessBlock(byte[] inBuf, int inOff, byte[] outBuf, int outOff)
    {
       return ProcessBlock(inBuf.AsSpan(inOff), outBuf.AsSpan(outOff));
    }

    
    public int ProcessBlock(ReadOnlySpan<byte> input, Span<byte> output)
    {
        int blockSize = BlockSizeInBytes;
        
        Guard.ValidLength(input, blockSize, "input buffer too short");
        Guard.ValidLength(output, blockSize, "output buffer too short");
        
        ProcessBytes(input[.._blockSize], output);
        
        return _blockSize;
    }

    public byte ReturnByte(byte input)
    {
        return CalculateByte(input);
    }
    
    private void IncrementCounterAt(int posStart)
    {
        int carry = _delta;
        
        for (int i = posStart; i < _ofbV.Length && carry > 0; i++)
        {
            int sum = (_ofbV[i] & 0xFF) + carry;
            _ofbV[i] = (byte)(sum & 0xFF);
            carry = sum >> 8; 
        }
    }

    private byte CalculateByte(byte b)
    {
        if (_byteCount == 0)
        {
            
            // default 0 pos
            IncrementCounterAt(0);

            _cipherEngine.ProcessBlock(_ofbV, 0, _ofbOutV, 0);

            return (byte)(_ofbOutV[_byteCount++] ^ b);
        }

        byte rv = (byte)(_ofbOutV[_byteCount++] ^ b);

        if (_byteCount == _ofbV.Length)
        {
            _byteCount = 0;
        }

        return rv;
    }

    private int GenerateRandomDelta()
    {
       
        ReadOnlySpan<byte> halfIv = _iv.AsSpan(_blockSize / 2);
        
        int delta = 0;
        
        // convert it to a positive number
        foreach (byte b in halfIv)
        {
            delta = (delta << 8) | b;
        }
        
        delta = Math.Clamp(delta, 1, 255);
        
        if ((delta & 1) == 0)
        {
            delta = (delta == 255) ? delta - 1 : delta + 1;
        }
    
        return delta;
    }
    
    public void Reset()
    {
        if (_initialized)
        {
            _cipherEngine.ProcessBlock(_iv, 0, _ofbV, 0);
        }
        
        _byteCount = 0;
    }
    
    #endregion
    
}