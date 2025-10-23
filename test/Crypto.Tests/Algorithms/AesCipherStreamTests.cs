using Crypto.Domain.Enums;
using Crypto.Domain.Interfaces;
using Crypto.Generators;
using Crypto.Tests.Base;

namespace Crypto.Tests.IO;

public class AesCipherStreamTests : BlockCipherStreamTests
{
    protected override ICipherOperator CreateCipherOperator() => CryptoBuilder
        .UseAes()
        .WithMode(builder => builder.UseCbcMode())
        .AddPadding(BlockPadding.PKCS7)
        .Build();

    protected override ISymmetricKeyGenerator CreateKeyGenerator() => 
        new AesKeyGenerator(new CryptoRandom(), 256);
}