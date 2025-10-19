namespace Crypto.Domain.Interfaces;

public interface IKeyGenerator<out TKey>
{
    
    IRandomGenerator RandomGen { get; }
    
    int KeySize { get; }
    
    TKey GenerateKey();
    
}