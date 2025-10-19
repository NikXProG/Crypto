using System.Numerics;
using Crypto.Domain.Interfaces;

namespace Crypto.Utils;

public abstract class PrimalityTest : IPrimalityTest
{
    protected readonly IRandomGenerator _randomGen;
    
    protected PrimalityTest(IRandomGenerator randomGen)
    {
        _randomGen = randomGen ??  throw new ArgumentNullException(nameof(randomGen));
    }
    
    public bool IsProbablyPrime(BigInteger n, double probability)
    {
        if (probability < 0.5 || probability >= 1)
        {
            throw new ArgumentOutOfRangeException(
                nameof(probability),
                "The probability must be in the range [0.5, 1)");
        }
        
        int iterations = CalculateIterations(probability);
        
        return IsProbablyPrime(n, iterations);
    }

    public bool IsProbablyPrime(BigInteger n, int iterations)
    {
        
        while (--iterations > 0)
        {
            if (!RunTest(n))
            {
                return false;
            }
            
        }
            
        return true;
    }
    
    public abstract bool RunTest(BigInteger n);

    public abstract int CalculateIterations(double minProbability);

    public virtual BigInteger GetRandomBase(BigInteger n)
    {
        BigInteger a;
        do
        {
            // Генерируем случайное число от 2 до n-2
            byte[] bytes = n.ToByteArray();
            _randomGen.NextBytes(bytes);
            a = new BigInteger(bytes);
            a = BigInteger.Abs(a) % (n - 2) + 2;
            
        } while (CryptoPrimeCore.Gcd(a, n) != 1);
            
        return a;
    }
    

}