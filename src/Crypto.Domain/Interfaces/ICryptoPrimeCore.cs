using System.Numerics;
using Crypto.Domain.ValueObjects;

namespace Crypto.Domain.Interfaces;

public interface ICryptoPrimeCore
{
    int LegendreSymbol(BigInteger a, BigInteger p);
        
    int JacobiSymbol(BigInteger a, BigInteger n);
    
    BigInteger Gcd(BigInteger a, BigInteger b);

    ExtendedGcdResult ExtendedGcd(BigInteger a, BigInteger b);

    BigInteger ModularExponentiation(BigInteger a, BigInteger b, BigInteger m);

}