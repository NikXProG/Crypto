using Crypto.Ciphers;
using Crypto.Core.Interfaces;
using Crypto.Core;
using Crypto.Symmetrical;
using Crypto.Symmetrical.Algorithms;
using Crypto.Symmetrical.Builders;
using Crypto.Symmetrical.Generators;

namespace Crypto
{
    public class CryptoFactory
    {
        
        public static ISymmetrical CreateDes(byte[] key, byte[] iv)
        {
            return new DesCipher()
            {
                Key = key,
                IV = iv
            };
        }

        public static ISymmetrical CreateTripleDes()
        {
            return new TripleDes();
        }
        
    }
}

