using System.Numerics;
using Crypto.Domain.Interfaces;
using Crypto.Helpers;

namespace Crypto.Utils;

public class MillerRabinTest : PrimalityTest
{

    public MillerRabinTest(IRandomGenerator randomGen)  : base(randomGen)
    { 
        
    }
    
    public override bool RunTest(BigInteger n)
    {
        
        BigInteger a = GetRandomBase(n);
        
        BigInteger d = n - 1;
        int s = 0;
        while (d % 2 == 0)
        {
            d /= 2;
            s++;
        }
        
        BigInteger x = a.ModExp(d, n);
            
        if (x == 1 || x == n - 1)
            return true;
            
        for (int i = 0; i < s - 1; i++)
        {
            x = x.ModExp(2, n);
            if (x == n - 1)
                return true;
            if (x == 1)
                return false;
        }
            
        return false;
    }

    public override int CalculateIterations(double probability)
    {
        // For the Miller-Rabin test: error probability ≤ 1/4^k
        return (int)Math.Ceiling(Math.Log(1 - probability) / Math.Log(0.25));
    }
    
    
}