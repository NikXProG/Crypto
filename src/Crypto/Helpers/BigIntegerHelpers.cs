using System.Numerics;
using Crypto.Domain.ValueObjects;
using Crypto.Utils;

namespace Crypto.Helpers;

internal static class BigIntegerHelpers
{

    internal static BigInteger ModExp(
        this BigInteger number,
        BigInteger exponent,
        BigInteger modulus)
    {
        return CryptoPrimeCore.ModExp(number, exponent, modulus);
    }

    internal static BigInteger Gcd(
        this BigInteger a, 
        BigInteger b)
    {
        return CryptoPrimeCore.Gcd(a, b);
    }
    
    internal static ExtendedGcdResult ExtendedGcd(
        this BigInteger a, 
        BigInteger b)
    {
        return CryptoPrimeCore.ExtendedGcd(a, b);
    }
    
    internal static int JacobiSymbol(
        this BigInteger a, 
        BigInteger b)
    {
        return CryptoPrimeCore.JacobiSymbol(a, b);
    }
    
    internal static int LegendreSymbol(
        this BigInteger a, 
        BigInteger b)
    {
        return CryptoPrimeCore.LegendreSymbol(a, b);
    }

    internal static bool CheckOnSmallPrime(
        this BigInteger a)
    {
        return CryptoPrimeCore.HasSmallPrimeFactor(a);
    }
    
    internal static BigInteger ModInverse(this BigInteger a, BigInteger m)
    {
        if (m <= 1)
            throw new ArgumentException("Modulus must be greater than 1", nameof(m));

        a %= m;
        if (a < 0)
            a += m;

        var result = CryptoPrimeCore.ExtendedGcd(a, m);
        
        if (result.Gcd != 1)
            throw new ArithmeticException("Modular inverse does not exist");
        
        BigInteger inverse = result.X % m;
        if (inverse < 0)
            inverse += m;

        return inverse;
    }
    
}