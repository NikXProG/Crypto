using Crypto.Domain.ValueObjects;

namespace Crypto.Domain.Interfaces;

public interface IAsymmetricKeyGenerator : IKeyGenerator<AsymmetricKeyPair>, IParamSetup
{
    
    IPrimalityTest PrimalityTest { get; }
 
}