using System.Numerics;
using Crypto.Domain.Interfaces;

namespace Crypto.Utils;

public class FermatTest : PrimalityTest
{
    
    public FermatTest(IRandomGenerator randomGen) : base(randomGen) { }
    
    public override bool RunTest(BigInteger n)
    {
        if (n < 2) return false;
        if (n == 2 || n == 3) return true;
        if (n % 2 == 0) return false;
        
        BigInteger a = GetRandomBase(n);
        
        BigInteger modExp = CryptoPrimeCore.ModExp(a, n - 1, n);

        return modExp == 1;
    }

    public override int CalculateIterations(double minProbability)
    {
        // probability ≤ 1/2^k
        return (int)Math.Ceiling(Math.Log(1 - minProbability) / Math.Log(0.5));
    }
    
}