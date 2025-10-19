using System.Numerics;
using Crypto.Domain.Enums;
using Crypto.Domain.Interfaces;
using Crypto.Domain.Parameters;
using Crypto.Generators;
using Crypto.Utils;

namespace Crypto.Builders;

public class RsaKeyGeneratorBuilder : IRsaGeneratorBuilder
{
    
    private int _keySize = 2048;
    private int _certainty = 100;
    private BigInteger _publicExponent = new BigInteger(65537);
    private PrimalityTestMode _primalityTestMode = PrimalityTestMode.Miller;
    private IRandomGenerator _randomGen = new CryptoRandom();
    
    public IRsaGeneratorBuilder WithKeySize(int keySize)
    {
        _keySize = keySize;
        return this;
    }

    public IRsaGeneratorBuilder WithCertaintyTest(int certainty)
    {
        _certainty = certainty;
        return this;
    }

    public IRsaGeneratorBuilder WithPublicExponent(BigInteger integer)
    {
        _publicExponent = integer;
        return this;
    }

    public IRsaGeneratorBuilder WithPrimalityMode(PrimalityTestMode mode)
    {
        _primalityTestMode = mode;
        return this;
    }
    
    public IRsaGeneratorBuilder WithRandom(IRandomGenerator randomGen)
    {
        _randomGen = randomGen ?? throw new ArgumentNullException(nameof(randomGen));
        return this;
    }

    public IAsymmetricKeyGenerator Build()
    {
     
        IPrimalityTest primalityTest = _primalityTestMode switch
        {
            PrimalityTestMode.Miller => new MillerRabinTest(randomGen: _randomGen),
            PrimalityTestMode.Strassen => new SolovayStrassenPrimalityTest(randomGen: _randomGen),
            PrimalityTestMode.Fermat => new FermatTest(randomGen: _randomGen),
            _ => throw new ArgumentOutOfRangeException(nameof(_primalityTestMode), _primalityTestMode, null)
        };
        
        var rsaGenerator = new RsaKeyGenerator(
            _randomGen,
            keySize: _keySize,
            primalityTest);

        rsaGenerator.Setup(
            new RsaGeneratorParams(
                _publicExponent,
                certainty: _certainty));

        return rsaGenerator;
    }
}