using Crypto.Domain.Enums;
using Crypto.Domain.Interfaces;
using Crypto.Generators;
using Crypto.Tests.Algorithms;
using Crypto.Tests.Base;

namespace Crypto.Tests.IO;

public class DealCipherStreamTests : BlockCipherStreamTests
{ 
    protected override ICipherOperator CreateCipherOperator() => CryptoBuilder
        .UseDeal()
        .WithMode(builder => builder.UseCbcMode())
        .AddPadding(BlockPadding.ISO10126)
        .Build();

    protected override ISymmetricKeyGenerator CreateKeyGenerator() => 
        new DealKeyGenerator(new CryptoRandom(), 256);
    
}