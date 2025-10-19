using Crypto.Domain.Interfaces;
using Crypto.Helpers;
using Crypto.Parameters;
using Crypto.Utils;

namespace Crypto.Operators;

public class BlockCipherOperator : ICipherOperator
{
    
    #region Fields
    
    protected byte[] _buf;
    protected int _bufOff;
    protected bool _encrypting;
    
    protected readonly IBlockCipherMode _cipherMode;
    
    #endregion
    
    #region Constructors
    
    public BlockCipherOperator(IBlockCipherMode cipherMode)
    {
        ArgumentNullException.ThrowIfNull(cipherMode);
        
        int blockSize = cipherMode.BlockSizeInBytes;
        
        if (blockSize < 1)
            throw new ArgumentException("must have a positive block size", nameof(cipherMode));

        _cipherMode = cipherMode;
        
        _buf = new byte[blockSize];
        _bufOff = 0;
    }

    #endregion

    #region Properties
    
    public int BlockSize => _cipherMode.BlockSizeInBytes;
    
    #endregion

    #region Methods

    public virtual void Setup(bool encrypting, ICryptoParams key)
    {
        _encrypting = encrypting;
        
        Reset();
        
        _cipherMode.Setup(encrypting, key);
    }

    public virtual int GetOutputSize(int length) => _bufOff + length;
    
    public virtual int GetUpdateOutputSize(int length) =>
        OperatorHelpers.GetFullBlocksSize(totalSize: _bufOff + length, blockSize: _buf.Length);

    #region Processing Byte

    public virtual byte[] ProcessByte(byte input)
    {
        int updateOutputSize = GetUpdateOutputSize(1);

        byte[] output = updateOutputSize > 0 ? new byte[updateOutputSize] : null;

        int outLen = ProcessByte(input, output, 0);

        if (updateOutputSize > 0 && outLen < updateOutputSize)
            return ArrayHelpers.CopyOf(output, outLen);

        return output;
    }
    
    public virtual int ProcessByte(byte input, byte[] output, int outOff)
    {
        return ProcessByte(input, 
            SpanHelpers.FromNullable(output,  outOff));
    }

    public virtual int ProcessByte(byte input, Span<byte> output)
    {
        _buf[_bufOff++] = input;

        if (_bufOff != _buf.Length) return 0;
        
        Guard.ValidLength(output, _buf.Length, "output buffer too short");

        _bufOff = 0;
        return _cipherMode.ProcessBlock(_buf, output);
    }

    #endregion

    #region Processing blocks
    
    public virtual byte[] ProcessBlocks(byte[] input, int inOff, int length)
    {
        if (input == null)
            throw new ArgumentNullException(nameof(input));
        if (length < 1)
            return null;

        int updateOutputSize = GetUpdateOutputSize(length);

        byte[]? output = updateOutputSize > 0 ? new byte[updateOutputSize] : null;

        int outLen = ProcessBlocks(input, inOff, length, output, 0);

        if (updateOutputSize > 0 && outLen < updateOutputSize)
            return ArrayHelpers.CopyOf(output, outLen);

        return output;
    }

    public virtual int ProcessBlocks(byte[] input, int inOff, int length, byte[] output, int outOff)
    {
        if (length < 1)
        {
            return length < 0 ? throw new ArgumentException("Can't have a negative input length!") : 0;
        }
        
        return ProcessBlocks(
            input.AsSpan(inOff, length), 
            SpanHelpers.FromNullable(output, outOff));
    }

    public virtual int ProcessBlocks(ReadOnlySpan<byte> input, Span<byte> output)
    {
        int resultLen = 0;
        int blockSize = _buf.Length;
        int available = blockSize - _bufOff;

        if (input.Length >= available)
        {
            int updateOutputSize = GetUpdateOutputSize(input.Length);
            
            Guard.ValidLength(output, updateOutputSize, "output buffer too short");

            input[..available].CopyTo(_buf.AsSpan(_bufOff));
            input = input[available..];

            // Handle destructive overlap by copying the remaining input
            if (output[..blockSize].Overlaps(input))
            {
                byte[] tmp = new byte[input.Length];
                input.CopyTo(tmp);
                input = tmp;
            }

            resultLen = _cipherMode.ProcessBlock(_buf, output);
            _bufOff = 0;

            while (input.Length >= blockSize)
            {
                resultLen += _cipherMode.ProcessBlock(input, output[resultLen..]);
                input = input[blockSize..];
            }
        }

        input.CopyTo(_buf.AsSpan(_bufOff));
        _bufOff += input.Length;
        return resultLen;
    }

    #endregion
    
    #region Processing blocks final

    public virtual int ProcessBlockFinal(byte[] output, int outOff)
    {
        return ProcessBlockFinal(SpanHelpers.FromNullable(output, outOff));
    }

    public virtual int ProcessBlockFinal(Span<byte> output)
    {
        try
        {
            if (_bufOff != 0)
            {
                Guard.ValidLength(!_cipherMode.IsPartialBlockOkay, "data not block size aligned");
                Guard.ValidLength(output, _bufOff, "output buffer too short for DoFinal()");
              
                _cipherMode.ProcessBlock(_buf, _buf);
                _buf.AsSpan(0, _bufOff).CopyTo(output);
            }

            return _bufOff;
        }
        finally
        {
            Reset();
        }
    }

    #endregion
    
    #region Processing all blocks
    
    public virtual byte[] ProcessAll(byte[] input, int inOff, int inLen)
    {
        if (input == null)
            throw new ArgumentNullException(nameof(input));

        int outputSize = GetOutputSize(inLen);
        if (outputSize < 1)
        {
            Reset();
            return Array.Empty<byte>();
        }

        byte[] output = new byte[outputSize];

        int outLen = inLen > 0 ? ProcessBlocks(input, inOff, inLen, output, 0) : 0;
        outLen += ProcessBlockFinal(output, outLen);

        return outLen < outputSize ? ArrayHelpers.CopyOf(output, outLen) : output;
    }
    
    #endregion
    
    public virtual void Reset()
    {
        Array.Clear(_buf, 0, _buf.Length);
        _bufOff = 0;

        _cipherMode.Reset();
    }
    
    #endregion
    
    
    
}