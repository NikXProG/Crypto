using System;
using System.Collections.Generic;
using System.Numerics;
using Crypto.Domain.Parameters;
using Crypto.Helpers;

public class WienerAttack
{
    


    public static RsaCrtKey? Run(BigInteger e, BigInteger N)
    {
        if (e <= 1)
            throw new ArgumentException("Public exponent must be greater than 1", nameof(e));
        
        if (N <= e)
            throw new ArgumentException("Modulus must be greater than public exponent", nameof(N));

        var convergents = ComputeConvergents(e, N);
        
        foreach (var convergent in convergents)
        {
            if (TryFactorWithConvergent(e, N, convergent.Numerator, convergent.Denominator, out var p, out var q))
            {
                BigInteger p1 = p - 1;
                BigInteger q1 = q - 1;
                BigInteger gcd = BigInteger.GreatestCommonDivisor(p1, q1);
                BigInteger lcm = (p1 / gcd) * q1;
        
                BigInteger d = e.ModInverse(lcm);
        
                BigInteger dP = d % p1;
                BigInteger dQ = d % q1;
                
                BigInteger qInv = q.ModInverse(p);
            
                return new RsaCrtKey(N,e, d, p, q, dP, dQ, qInv);
            }
        }

        return null;
    }
    public static bool IsVulnerable(BigInteger publicExponent, BigInteger modulus, int maxTests = 1000)
    {
        try
        {
            var convergents = ComputeConvergents(publicExponent, modulus);
            int tested = 0;
            
            foreach (var convergent in convergents)
            {
                if (TryFactorWithConvergent(publicExponent, modulus, convergent.Numerator, convergent.Denominator, out _, out _))
                    return true;
                    
                if (++tested >= maxTests)
                    break;
            }
            
            return false;
        }
        catch
        {
            return false;
        }
    }

    private static IEnumerable<Fraction> ComputeConvergents(BigInteger a, BigInteger b)
    {
        List<Fraction> convergents = new List<Fraction>();
        BigInteger hPrev2 = 0, kPrev2 = 1;
        BigInteger hPrev1 = 1, kPrev1 = 0;

        while (b != 0)
        {
            BigInteger quotient = a / b;
            BigInteger remainder = a % b;
            
            BigInteger hCurrent = quotient * hPrev1 + hPrev2;
            BigInteger kCurrent = quotient * kPrev1 + kPrev2;

            convergents.Add(new Fraction(hCurrent, kCurrent));
            
            hPrev2 = hPrev1;
            kPrev2 = kPrev1;
            hPrev1 = hCurrent;
            kPrev1 = kCurrent;

            a = b;
            b = remainder;
        }

        return convergents;
    }

    private static bool TryFactorWithConvergent(BigInteger e, BigInteger n,
        BigInteger k, BigInteger d, out BigInteger p, out BigInteger q)
    {
        p = 0;
        q = 0;
        
        if (k == 0) return false;

        // Проверяем, что (e*d - 1) делится на k нацело
        BigInteger edMinusOne = e * d - 1;
        if (edMinusOne % k != 0) return false;

        BigInteger phi = edMinusOne / k;
        BigInteger sum = n - phi + 1;  // p + q
        BigInteger discriminant = sum * sum - 4 * n;  // (p - q)^2

        if (discriminant.Sign < 0) return false;
        
        BigInteger sqrt = IntegerSqrt(discriminant);
        if (sqrt * sqrt != discriminant) return false;

        p = (sum + sqrt) / 2;
        q = (sum - sqrt) / 2;
        
        return p * q == n && p > 1 && q > 1;
        
    }

    private static BigInteger IntegerSqrt(BigInteger n)
    {
        if (n == 0) return 0;
        if (n < 0) throw new ArgumentException("Cannot compute square root of negative number");
        
        BigInteger x = n;
        BigInteger y = (x + 1) / 2;
        
        while (y < x)
        {
            x = y;
            y = (x + n / x) / 2;
        }
        
        return x;
    }
    
}



public class RsaFactors
{
    
    public BigInteger P { get; }
    public BigInteger Q { get; }

    public RsaFactors(BigInteger p, BigInteger q)
    {
        P = p;
        Q = q;
    }
    
    public void Deconstruct(out BigInteger p, out BigInteger q)
    {
        p = P;
        q = Q;
    }
    
    public override string ToString() => $"P: {P}, Q: {Q}";
    
}



public class Fraction
{
    public BigInteger Numerator { get; set; }
    public BigInteger Denominator { get; set; }

    public Fraction(BigInteger numerator, BigInteger denominator)
    {
        Numerator = numerator;
        Denominator = denominator;
    }

    public BigInteger Floor()
    {
        return Numerator / Denominator;
    }

    public Fraction Remainder()
    {
        return new Fraction(Numerator % Denominator, Denominator);
    }
    
    public override string ToString()
    {
        return $"{Numerator}/{Denominator}";
    }
}

