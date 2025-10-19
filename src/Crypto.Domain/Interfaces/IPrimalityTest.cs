using System.Numerics;

namespace Crypto.Domain.Interfaces;


public interface IPrimalityTest
{
    /// <summary>
    /// The test is performed primely
    /// </summary>
    /// <param name="n">The number being tested</param>
    /// <param name="minProbability">Minimum primality protection [0.5, 1)</param>
    /// <param name="random"></param>
    /// <returns>True if the number is probable prime</returns>
    bool IsProbablyPrime(BigInteger n, double minProbability);

    bool IsProbablyPrime(BigInteger n, int iterations);
    bool RunTest(BigInteger n);
    
    int CalculateIterations(double minProbability);

    BigInteger GetRandomBase(BigInteger n);
    
}
