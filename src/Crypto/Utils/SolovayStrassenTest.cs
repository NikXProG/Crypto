
using Crypto.Domain.Interfaces;
using Crypto.Helpers;

namespace Crypto.Utils;

using System;
using System.Numerics;

public class SolovayStrassenPrimalityTest : PrimalityTest
{

    public SolovayStrassenPrimalityTest(IRandomGenerator randomGen) : base(randomGen)
    {
        
    }
    
    public override bool RunTest(BigInteger n)
    {
      
        if (n < 2) return false;
        if (n == 2 || n == 3) return true;
        if (n % 2 == 0) return false;
        
        BigInteger a = GetRandomBase(n);
        
        int jacobi = a.JacobiSymbol(n);
        if (jacobi == 0) return false; 
        
        BigInteger modExp = a.ModExp((n - 1) / 2, n);
        
        BigInteger jacobiModN = (jacobi == -1) ? n - 1 : jacobi;

        return modExp == jacobiModN;
    }

    public override int CalculateIterations(double minProbability)
    {
        // probability < 1/2^k
        return (int)Math.Ceiling(Math.Log(1 - minProbability) / Math.Log(0.5));
    }
}