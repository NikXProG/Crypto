
using Crypto.Builders;
using Crypto.Domain.Enums;
using Crypto.Domain.Interfaces;
using Crypto.Engines;
using Crypto.Operators;

namespace Crypto;

public static class CryptoBuilder
{
    public static IBlockCipherBuilder UseDes() =>
        new BlockCipherBuilder(new DesEngine());

    public static IBlockCipherBuilder UseAes() =>
        new BlockCipherBuilder(new AesEngine());

    public static IAsymmetricalCipher UseRsa() =>
        new RsaEngine();
    
    public static IBlockCipherBuilder UseBlockCipher(BlockAlgorithm algorithm)
    {
        return algorithm switch
        {
            BlockAlgorithm.Aes => UseAes(),
            BlockAlgorithm.Des => UseDes(),
            _ => throw new ArgumentException($"Algorithm {algorithm} is not supported")
        };
    }
    
    public static IBlockCipherBuilder UseBlockCipher(IBlockCipher cipher)
        => new BlockCipherBuilder(cipher);
    
}