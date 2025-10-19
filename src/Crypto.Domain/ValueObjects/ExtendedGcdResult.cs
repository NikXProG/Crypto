using System.Numerics;

namespace Crypto.Domain.ValueObjects;

public record ExtendedGcdResult
{
    
    public ExtendedGcdResult(BigInteger gcd, BigInteger x, BigInteger y)
    {
        Gcd = gcd;
        X = x;
        Y = y;
    }
    
    public BigInteger Gcd { get; }
    public BigInteger X { get; }
    public BigInteger Y { get; }
    
    public bool Verify(BigInteger a, BigInteger b)
    {
        return a * X + b * Y == Gcd;
    }
    
}