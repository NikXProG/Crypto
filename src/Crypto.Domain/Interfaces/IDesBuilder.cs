using Crypto.Domain.Enums;

namespace Crypto.Domain.Interfaces
{
    
    public interface IDesBuilder
    {
        
        IDesBuilder WithPadding(BlockPadding blockPadding);
        
        ICipherOperator Build();
    
    }
    
}
