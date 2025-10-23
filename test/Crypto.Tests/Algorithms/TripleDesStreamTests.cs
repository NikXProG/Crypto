using Crypto.Domain.Enums;
using Crypto.Domain.Interfaces;
using Crypto.Generators;
using Crypto.Tests.Algorithms;
using Crypto.Tests.Base;

namespace Crypto.Tests.IO;

public class TripleDesStreamTests : BlockCipherStreamTests
{
    protected override ICipherOperator CreateCipherOperator() => CryptoBuilder
        .Use3Des()
        .WithMode(builder => builder.UseCbcMode())
        .AddPadding(BlockPadding.PKCS7)
        .Build();

    protected override ISymmetricKeyGenerator CreateKeyGenerator() => 
        new TripleDesKeyGenerator(new CryptoRandom(),128);
    
}