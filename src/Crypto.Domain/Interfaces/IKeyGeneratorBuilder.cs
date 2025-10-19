namespace Crypto.Domain.Interfaces;

public interface IKeyGeneratorBuilder<out TBuilder>
{
    
    TBuilder WithKeySize(int keySize);
    TBuilder WithRandom(IRandomGenerator randomGen);
    
}