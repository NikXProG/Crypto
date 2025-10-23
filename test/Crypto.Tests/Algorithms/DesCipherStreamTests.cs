using Crypto.Domain.Enums;
using Crypto.Domain.Exceptions;
using Crypto.Domain.Interfaces;
using Crypto.Domain.Parameters;
using Crypto.Generators;
using Crypto.Tests.Base;

namespace Crypto.Tests.IO;

public class DesCipherStreamTests : BlockCipherStreamTests
{
    protected override ICryptoParams CreateSymmetricParams(ICryptoParams paramKey, byte[] iv = null)
    {
        return paramKey;
    }

    protected override ICipherOperator CreateCipherOperator() => CryptoBuilder
        .UseDes()
        .WithMode(builder => builder.UseEcbMode())
        .AddPadding(BlockPadding.PKCS7)
        .Build();

    protected override ISymmetricKeyGenerator CreateKeyGenerator() => 
        new DesKeyGenerator(new CryptoRandom());
    
    
}