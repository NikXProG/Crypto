using Crypto.CipherModes;
using Crypto.Domain.Enums;
using Crypto.Domain.Interfaces;

namespace Crypto.Builders;

public class BlockCipherModeModeBuilder : IBlockCipherModeBuilder
{
    private int _feedbackSize = 0; // not init

    private Domain.Enums.CipherMode _cipherMode = Domain.Enums.CipherMode.ECB;

    private readonly IBlockCipher _engine;

    private CtrCounterMode _ctrCounterMode = CtrCounterMode.One;
    
    private byte[] _iv;

    public BlockCipherModeModeBuilder(IBlockCipher engine)
    {
        _engine = engine ?? throw new ArgumentNullException(nameof(engine));
    }

    public IBlockCipherModeBuilder UseMode(Domain.Enums.CipherMode mode)
    {
        if (Domain.Enums.CipherMode.CBC < mode && mode > Domain.Enums.CipherMode.CTR)
        {
            throw new ArgumentOutOfRangeException(nameof(mode));
        }
        _cipherMode = mode;
        return this;
    }

    public IBlockCipherModeBuilder WithIV(byte[] iv)
    {
        _iv = iv ?? throw new ArgumentNullException(nameof(iv));
        return this;
    }

    public IBlockCipherModeBuilder WithFeedbackSize(int feedbackSize)
    {
        _feedbackSize = feedbackSize;
        return this;
    }

    public IBlockCipherModeBuilder WithCtrCounterMode(CtrCounterMode mode)
    {
        if (CtrCounterMode.One < mode && mode > CtrCounterMode.RandomDelta)
        {
            throw new ArgumentOutOfRangeException(nameof(mode));
        }
        _ctrCounterMode = mode;
        return this;
    }

    public IBlockCipherModeBuilder UseCbcMode()
    {
        _cipherMode =  Domain.Enums.CipherMode.CBC;
        return this;
    }

    public IBlockCipherModeBuilder UseCfbMode()
    {
        _cipherMode = Domain.Enums.CipherMode.CFB;
        return this;
    }

    public IBlockCipherModeBuilder UseEcbMode()
    {
        _cipherMode = Domain.Enums.CipherMode.ECB;
        return this;
    }

    public IBlockCipherMode Build()
    {
        
        if (_engine == null)
        {
            throw new ArgumentException("No engine specified. Use `UseCipher(IBlockCipher engine)`");
        }
     
        return _cipherMode switch
        {
            Domain.Enums.CipherMode.CBC => BuildCbc(),
            Domain.Enums.CipherMode.PCBC => BuildPcbc(),
            Domain.Enums.CipherMode.CFB => BuildCfb(),
            Domain.Enums.CipherMode.OFB => BuildOfb(),
            Domain.Enums.CipherMode.ECB => BuildEcb(),
            Domain.Enums.CipherMode.CTR => BuildCtr(),
            Domain.Enums.CipherMode.CTRD => BuildDeltaCtr(),
            _ => throw new NotImplementedException($"Mode {_cipherMode} is not supported")
        };
    }

    private IBlockCipherMode BuildCbc() => new CbcBlockCipherMode(_engine, _iv);
    
    private IBlockCipherMode BuildPcbc() => new PcbcBlockCipherMode(_engine, _iv);
    
    private IBlockCipherMode BuildCfb()
    {
        return new CfbBlockCipherMode(_engine,  
            (_feedbackSize < 1) ? _engine.BlockSizeInBytes * 8 : _feedbackSize,
            _iv);
    }
    
    private IBlockCipherMode BuildOfb() => new OfbBlockCipherMode(_engine, _iv);
    
    private IBlockCipherMode BuildEcb() => new EcbBlockCipherMode(_engine);
    
    
    private IBlockCipherMode BuildCtr() => new DCtrBlockCipherMode(_engine, CtrCounterMode.One, _iv);
    
    private IBlockCipherMode BuildDeltaCtr() => new DCtrBlockCipherMode(_engine, _ctrCounterMode, _iv);
    
}