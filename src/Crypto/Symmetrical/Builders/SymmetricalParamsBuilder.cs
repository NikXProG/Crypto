using Crypto.Core;
using Crypto.Symmetrical.Parameters;

namespace Crypto.Symmetrical.Builders;

public class SymmetricalParamsBuilder
{
    
    private int _keySize;
    private int _blockSize;
    private int _feedbackSize;
    private CipherMode _mode;
    private PaddingMode _padding;
    private byte[] _key;
    private byte[] _iv;
    
    public SymmetricalParamsBuilder WithKeySize(int keySize)
    {
        _keySize = keySize;
        return this;
    }

    public SymmetricalParamsBuilder WithBlockSize(int blockSize)
    {
        _blockSize = blockSize;
        return this;
    }

    public SymmetricalParamsBuilder WithFeedbackSize(int feedbackSize)
    {
        _feedbackSize = feedbackSize;
        return this;
    }

    public SymmetricalParamsBuilder WithMode(CipherMode mode)
    {
        _mode = mode;
        return this;
    }

    public SymmetricalParamsBuilder WithPaddingMode(PaddingMode padding)
    {
        _padding = padding;
        return this;
    }

    public SymmetricalParamsBuilder WithKey(byte[] key)
    {
        _key = key;
        return this;
    }

    public SymmetricalParamsBuilder WithIV(byte[] iv)
    {
        _iv = iv;
        return this;
    }

    public SymmetricalParameters Build()
    {
        return new SymmetricalParameters(
            _keySize,
            _blockSize,
            _feedbackSize,
            _mode,
            _padding,
            _key,
            _iv);
    }
}