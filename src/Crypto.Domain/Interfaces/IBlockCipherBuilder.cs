using Crypto.Domain.Enums;

namespace Crypto.Domain.Interfaces;

public interface IBlockCipherBuilder
{
    
    IBlockCipherBuilder WithMode(Action<IBlockCipherModeBuilder> modeBuilder);
    
    IBlockCipherBuilder AddPadding(BlockPadding padding);
    
    ICipherOperator Build();
    

}