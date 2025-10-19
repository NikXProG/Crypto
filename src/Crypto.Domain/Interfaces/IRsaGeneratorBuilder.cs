using System.Numerics;
using Crypto.Domain.Enums;

namespace Crypto.Domain.Interfaces;

public interface IRsaGeneratorBuilder : IKeyGeneratorBuilder<IRsaGeneratorBuilder>
{
    
    IRsaGeneratorBuilder WithPrimalityMode(PrimalityTestMode mode);
    IRsaGeneratorBuilder WithPublicExponent(BigInteger integer);
    IRsaGeneratorBuilder WithCertaintyTest(int certainty);
    IAsymmetricKeyGenerator Build();
    
}