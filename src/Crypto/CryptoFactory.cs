using Crypto.Core.Interfaces;
using Crypto.Core;
using Crypto.Symmetrical;
using Crypto.Symmetrical.Algorithms;
using Crypto.Symmetrical.Builders;

namespace Crypto
{
    public class CryptoFactory
    {
        
        public static ISymmetrical CreateDes(byte[] key, byte[] iv)
        {
            return new DesBuilder()
                .WithFeistelSize(FeistelNetSize.Large)
                .WithSymmetricalParams(
                    b => b
                        .WithIV(iv)
                        .WithKey(key)
                        .Build())
                .Build();
        }

        public static ISymmetrical CreateTripleDes()
        {
            return new TripleDes();
        }
        
    }
}

