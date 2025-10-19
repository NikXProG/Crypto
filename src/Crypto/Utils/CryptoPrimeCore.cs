using System.Numerics;
using Crypto.Domain.Interfaces;
using Crypto.Domain.ValueObjects;

namespace Crypto.Utils;

internal static class CryptoPrimeCore
{

    internal static readonly int[] primeList = new int[]
    {
        3, 5, 7, 11, 13, 17, 19, 23,
        29, 31, 37, 41, 43,
        47, 53, 59, 61, 67,
        71, 73, 79, 83,
        89, 97, 101, 103,
        107, 109, 113, 127,
        131, 137, 139, 149,
        151, 157, 163, 167,
        173, 179, 181, 191,
        193, 197, 199, 211,
        223, 227, 229,
        233, 239, 241,
        251, 257, 263,
        269, 271, 277,
        281, 283, 293,
        307, 311, 313,
        317, 331, 337,
        347, 349, 353,
        359, 367, 373,
        379, 383, 389,
        397, 401, 409,
        419, 421, 431,
        433, 439, 443,
        449, 457, 461,
        463, 467, 479,
        487, 491, 499,
        503, 509, 521,
        523, 541, 547,
        557, 563, 569,
        571, 577, 587,
        593, 599, 601,
        607, 613, 617,
        619, 631, 641,
        643, 647, 653,
        659, 661, 673,
        677, 683, 691,
        701, 709, 719,
        727, 733, 739,
        743, 751, 757,
        761, 769, 773,
        787, 797, 809,
        811, 821, 823,
        827, 829, 839,
        853, 857, 859,
        863, 877, 881,
        883, 887, 907,
        911, 919, 929,
        937, 941, 947,
        953, 967, 971,
        977, 983, 991,
        997, 1009, 1013,
        1019, 1021, 1031,
        1033, 1039, 1049,
        1051, 1061, 1063,
        1069, 1087, 1091,
        1093, 1097, 1103,
        1109, 1117, 1123,
        1129, 1151, 1153,
        1163, 1171, 1181,
        1187, 1193, 1201,
        1213, 1217, 1223,
        1229, 1231, 1237,
        1249, 1259, 1277,
        1279, 1283, 1289
    };

    internal static bool HasSmallPrimeFactor(BigInteger n)
    {
        foreach (int p in primeList)
        {
            if ((n % p) == 0)
                return n != p;
        }
        return false;
    }
    
    internal static int LegendreSymbol(BigInteger a, BigInteger p)
    {
        // Warning: the number must be prime, otherwise the result will be unpredictable
        if (p <= 2)
            throw new ArgumentException("p must be an odd prime");

        a %= p;
        if (a < 0)
            a += p;

        if (a == 0)
            return 0;
        if (a == 1)
            return 1;
        
        BigInteger exp = (p - 1) / 2;
        BigInteger result = ModExp(a, exp, p);

        if (result == p - 1)
            return -1;
        return (int)result;
    }

    internal static int JacobiSymbol(BigInteger a, BigInteger n)
    {
        if (n <= 0 || (n & 1) == 0)
            throw new ArgumentException("p must be an odd positive number");

        a %= n;
        if (a < 0) a += n;
        
        if (a == 0) return 0;
        if (a == 1) return 1;
    
        int result = 1;

        while (a != 0)
        {
            while ((a & 1) == 0)
            {
                a >>= 1;
                BigInteger r = n & 7;
                if (r == 3 || r == 5)
                    result = -result;
            }

            (a, n) = (n, a);

            if (((a & 3) == 3) && ((n & 3) == 3))
            {
                result = -result;
            }

            a %= n;
        }

        return n == 1 ? result : 0;
    }
    
    
    internal static BigInteger Gcd(BigInteger a, BigInteger b)
    {
        a = BigInteger.Abs(a);
        b = BigInteger.Abs(b);

        if (a == 0) return b;
        if (b == 0) return a;
        
        int shift = 0;
        while (((a | b) & 1) == 0) 
        {
            a >>= 1;
            b >>= 1;
            shift++;
        }

        while ((a & 1) == 0) a >>= 1; 

        while (b != 0)
        {
            while ((b & 1) == 0) b >>= 1; 

            if (a > b)
            {
                (a, b) = (b, a);
            }

            b -= a;
        }

        return a << shift;
    }
    
    internal static ExtendedGcdResult ExtendedGcd(BigInteger a, BigInteger b)
    {
        if (a == 0) return new ExtendedGcdResult(BigInteger.Abs(b), 0, b.Sign);
        if (b == 0) return new ExtendedGcdResult(BigInteger.Abs(a), a.Sign, 0);

        a = BigInteger.Abs(a);
        b = BigInteger.Abs(b);
        
        int shift = 0;
        while (((a | b) & 1) == 0)
        {
            a >>= 1;
            b >>= 1;
            shift++;
        }
        
        BigInteger u = a, v = b;
        BigInteger A = 1, B = 0, C = 0, D = 1;

        while (u != 0)
        {
            while ((u & 1) == 0)
            {
                u >>= 1;
                if ((A & 1) == 0 && (B & 1) == 0)
                {
                    A >>= 1; B >>= 1;
                }
                else
                {
                    A = (A + b) >> 1; B = (B - a) >> 1;
                }
            }

            while ((v & 1) == 0)
            {
                v >>= 1;
                if ((C & 1) == 0 && (D & 1) == 0)
                {
                    C >>= 1; D >>= 1;
                }
                else
                {
                    C = (C + b) >> 1; D = (D - a) >> 1;
                }
            }

            if (u >= v)
            {
                u -= v; A -= C; B -= D;
            }
            else
            {
                v -= u; C -= A; D -= B;
            }
        }
        
        return new ExtendedGcdResult(v << shift, C, D);
    }
    
    internal static BigInteger ModExp(BigInteger a, BigInteger b, BigInteger m)
    {
        if (m == 1) return 0; 
        if (b < 0) throw new ArgumentException("Exponent must be non-negative");

        a %= m;
        BigInteger result = 1;

        while (b > 0)
        {
            if ((b & 1) == 1) 
            {
                result = (result * a) % m;
            }
            a = (a * a) % m; 
            b >>= 1; 
        }

        return result;
    }
}