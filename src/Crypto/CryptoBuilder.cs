using Crypto.Core.Interfaces;
using Crypto.Symmetrical.Builders;

namespace Crypto;

public static class CryptoBuilder
{
    public static DesBuilder UseDesAlgorithm() => new DesBuilder();
    
    // public static AesBuilder CreateAes() 
    
}