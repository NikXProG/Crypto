using System.Numerics;
using System.Security.Cryptography;
using Crypto.Domain.Interfaces;
using Crypto.Domain.Parameters;
using Crypto.Domain.ValueObjects;
using Crypto.Helpers;
using Crypto.Utils;

namespace Crypto.Generators;

public class RsaKeyGenerator : IAsymmetricKeyGenerator
{

    #region Fields
    
    private readonly int _keySize;
    private readonly IPrimalityTest _primalityTest;
    private readonly IRandomGenerator _randomGen;
    
    protected static readonly BigInteger One = BigInteger.One;
    protected static readonly BigInteger DefaultPublicExponent = new BigInteger(65537);
    protected const int DefaultCertainty = 100;
    
    private RsaGeneratorParams _rsaParams;
    
    #endregion

    #region Constructors
    
    public RsaKeyGenerator(
        IRandomGenerator randomGen,
        int keySize,
        IPrimalityTest test)
    {
        _primalityTest = test ?? throw new ArgumentNullException(nameof(test));
        _randomGen = randomGen ??  throw new ArgumentNullException(nameof(randomGen));
        _keySize = keySize;
    }

    #endregion

    #region Properties
    
    public int KeySize => _keySize;

    public IRandomGenerator RandomGen => _randomGen;

    public IPrimalityTest PrimalityTest => _primalityTest;

    #endregion
    
    #region Methods

    public void Setup(ICryptoParams param)
    {
        if (param is not RsaGeneratorParams rsaParams)
        {
            throw new ArgumentException($"{nameof(param)} must be of type {nameof(RsaGeneratorParams)}");
        }
        
        _rsaParams = rsaParams;
    }


    public AsymmetricKeyPair GenerateKey()
    {
        if (_rsaParams == null)
        {
            _rsaParams = new RsaGeneratorParams(DefaultPublicExponent, DefaultCertainty);
        }
        
        while (true)
        {
            
            int pBitLength = (_keySize + 1) / 2;
            int qBitLength = _keySize - pBitLength;
            int minDiffBits = _keySize / 3;
            int minWeight = _keySize >> 2;
            
            BigInteger e = _rsaParams.PublicExponent;
            
            BigInteger p = ChooseRandomPrime(pBitLength,e);
            BigInteger q, n;
        
            while (true)
            {
                q = ChooseRandomPrime(qBitLength, e);
                
                if ((p - q).GetBitLength() < minDiffBits)
                    continue;
        
                n = p * q;
                
                if (n.GetBitLength() != _keySize)
                {
                    if (p < q) p = q;
                    continue;
                }
        
                if (HammingWeight(n) < minWeight)
                {
                    p = ChooseRandomPrime(pBitLength, e);
                    continue;
                }
        
                break;
            }
        
            if (p < q)
            {
                (p, q) = (q, p);
            }
        
            BigInteger p1 = p - 1;
            BigInteger q1 = q - 1;
            BigInteger gcd = p1.Gcd(q1);
            BigInteger lcm = (p1 / gcd) * q1;
        
            BigInteger d = e.ModInverse(lcm);
        
            BigInteger dP = d % p1;
            BigInteger dQ = d % q1;
            BigInteger qInv = q.ModExp(p - 2, p);
        
            return new AsymmetricKeyPair(
                new RsaKey(false, n, e),
                new RsaCrtKey(n, e, d, p, q, dP, dQ, qInv));
            
        }
        
    }

    private static int HammingWeight(BigInteger x)
    {
        int weight = 0;
        foreach (byte b in x.ToByteArray())
            weight += BitOperations.PopCount(b);
        return weight;
    }
    
    private BigInteger ChooseRandomPrime(int bitLength, BigInteger e)
    {
        int byteLength = (bitLength + 7) / 8;
        byte[] buffer = new byte[byteLength];
        
        while (true)
        {
            _randomGen.NextBytes(buffer);
            
            int extraBits = byteLength * 8 - bitLength;
            if (extraBits > 0)
                buffer[0] &= (byte)(0xFF >> extraBits);

            buffer[0] |= (byte)(1 << ((bitLength - 1) % 8));
            buffer[byteLength - 1] |= 1;
            
            BigInteger p = new BigInteger(buffer, isUnsigned: true);
            
            if (p % e == One)
                continue;

            if (p.CheckOnSmallPrime())
            {
                continue;
            }
            
            if (_primalityTest.IsProbablyPrime(p, _rsaParams.Certainty)) 
                return p;
            
            
        }
    
    }

    
    #endregion
    
}