
using Crypto.Domain.Enums;
using Crypto.Domain.Interfaces;
using Crypto.Generators;
using Crypto.Operators;
using Crypto.Padding;

namespace Crypto.Builders;

public class BlockCipherBuilder : IBlockCipherBuilder
{
    
    #region Fields
    
    private BlockPadding _padding = BlockPadding.PKCS7;

    private readonly BlockCipherModeModeBuilder _modeBuilder;

    #endregion
    
    #region Constructors
    
    public BlockCipherBuilder(IBlockCipher engine)
    {
        _modeBuilder =  new BlockCipherModeModeBuilder(engine ?? throw new ArgumentNullException(nameof(engine)));
    }
    
    #endregion
    
    #region Methods
    
    public static IBlockCipherBuilder Create(IBlockCipher engine) => new BlockCipherBuilder(engine);
    
    public IBlockCipherBuilder WithMode(Action<IBlockCipherModeBuilder> action)
    {
        action(_modeBuilder);
        return this;
    }

    public IBlockCipherBuilder AddPadding(BlockPadding padding)
    {
        _padding = padding;
        return this;
    }
    
    public ICipherOperator Build()
    {
       
        return _padding switch
        {
            BlockPadding.None => BuildNonePadding(),
            BlockPadding.Zeros => BuildZerosPadding(),
            BlockPadding.PKCS7 => BuildPKCS7Padding(),
            BlockPadding.ANSIX923 => BuildANSIX923Padding(),
            BlockPadding.ISO10126 => BuildISO10126Padding(),
            _ => throw new NotImplementedException($"Padding {_padding} is not supported")
        };
    }
    
    #region Private Methods

    private ICipherOperator BuildNonePadding()
    {
        return new BlockCipherOperator(_modeBuilder.Build());
    }
    
    private ICipherOperator BuildZerosPadding()
    {
        return new PaddedBlockCipherOperator(_modeBuilder.Build(), new ZerosPadding());
    }
    
    private ICipherOperator BuildPKCS7Padding()
    {
        return new PaddedBlockCipherOperator(_modeBuilder.Build(), new PKCS7Padding());
    }
    
    private ICipherOperator BuildISO10126Padding()
    {
        return new PaddedBlockCipherOperator(_modeBuilder.Build(), new ISO10126Padding(new CryptoRandom()));
    }

    private ICipherOperator BuildANSIX923Padding()
    {
        return new PaddedBlockCipherOperator(_modeBuilder.Build(),  new ANSIX923Padding(new CryptoRandom()));
    }

    #endregion
    
    #endregion
    
}