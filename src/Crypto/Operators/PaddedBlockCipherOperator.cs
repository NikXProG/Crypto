using Crypto.Domain.Interfaces;
using Crypto.Helpers;
using Crypto.Padding;
using Crypto.Parameters;
using Crypto.Utils;

namespace Crypto.Operators;

public class PaddedBlockCipherOperator : BlockCipherOperator
{
    
    #region Fields 
    
    private readonly IBlockCipherPadding _paddingMode;
    
    #endregion
    
    #region Constructors
    
    public PaddedBlockCipherOperator(
        IBlockCipherMode cipherMode) 
        : this(cipherMode, new PKCS7Padding())
    {
    }
    
    public PaddedBlockCipherOperator(
        IBlockCipherMode cipherMode,
        IBlockCipherPadding paddingMode) : base(cipherMode)
    {
        _paddingMode = paddingMode ?? throw new ArgumentNullException(nameof(paddingMode));
    }
    
    #endregion
    
    #region Methods

    public override void Setup(bool encrypting, ICryptoParams cryptoParamsPair)
    {
        _encrypting = encrypting;
        
        Reset();
        
        _cipherMode.Setup(encrypting, cryptoParamsPair);
    }

    public override int GetOutputSize(int length)
    {
        int totalSize = _bufOff + length;
        int blockSize = _buf.Length;

        return _encrypting
            ? OperatorHelpers.GetFullBlocksSize(totalSize, blockSize) + blockSize
            : OperatorHelpers.GetFullBlocksSize(totalSize + blockSize - 1, blockSize);
    }
    
    public override int GetUpdateOutputSize(int length) =>
        OperatorHelpers.GetFullBlocksSize(totalSize: _bufOff + length - 1, blockSize: _buf.Length);

    
    #region Processing byte

    public override int ProcessByte(byte input, byte[] output, int outOff)
    {
        return ProcessByte(input, SpanHelpers.FromNullable(output, outOff));
    }
    
    public override int ProcessByte(byte input, Span<byte> output)
    {
        int resultLen = 0;

        if (_bufOff == _buf.Length)
        {
            Guard.ValidLength(output, _buf.Length, "output buffer too short");

            resultLen = _cipherMode.ProcessBlock(_buf, output);
            _bufOff = 0;
        }

        _buf[_bufOff++] = input;

        return resultLen;
    }
    
    
    #endregion
    
    #region Processing blocks

    public override int ProcessBlocks(
        byte[] input,
        int inOff,
        int length,
        byte[] output,
        int outOff)
    {
        if (length < 1)
        {
            if (length < 0)
                throw new ArgumentException("Can't have a negative input length!");

            return 0;
        }
        
        return ProcessBlocks(
            input.AsSpan(inOff, length), 
            SpanHelpers.FromNullable(output, outOff));
    }
    
    public override int ProcessBlocks(ReadOnlySpan<byte> input, Span<byte> output)
    {
        int resultLen = 0;
        int blockSize = _buf.Length;
        int available = blockSize - _bufOff;

        if (input.Length > available)
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

            while (input.Length > blockSize)
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

    public override int ProcessBlockFinal(byte[] output, int outOff)
    {
        return ProcessBlockFinal(SpanHelpers.FromNullable(output, outOff));
    }

    public override int ProcessBlockFinal(Span<byte> output)
    {
        try
        {
            int resultLen = 0;
            int blockSize = _buf.Length;

            if (_encrypting)
            {
                if (_bufOff == blockSize)
                {
                    Guard.ValidLength(output, blockSize * 2, "output buffer too short");

                    resultLen = _cipherMode.ProcessBlock(_buf, output);
                    _bufOff = 0;
                }
                else
                {
                    Guard.ValidLength(output, blockSize, "output buffer too short");
                }

                _paddingMode.AddPadding(_buf, _bufOff);

                resultLen += _cipherMode.ProcessBlock(_buf, output[resultLen..]);
            }
            else
            {
                Guard.ValidLength(_bufOff != blockSize, "last block incomplete in decryption");

                resultLen = _cipherMode.ProcessBlock(_buf,_buf);
                //bufOff = 0;

                resultLen -= _paddingMode.PadCount(_buf);

                // We only restrict to the actual data, not the GetOutputSize bound
                Guard.ValidLength(output, resultLen, "output buffer too short");

                _buf.AsSpan(0, resultLen).CopyTo(output);
            }

            return resultLen;
        }
        finally
        {
            Reset();
        }
    }

    #endregion
    
    #region Processing all blocks

    public override byte[] ProcessAll(byte[] input, int inOff, int inLen)
    {
        ArgumentNullException.ThrowIfNull(input);

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

    #endregion
    
}