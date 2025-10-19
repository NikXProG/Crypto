using System.Numerics;

namespace Crypto.Domain.Parameters;

public class RsaKey : AsymmetricKey
{
    
    #region Fields
    
    private static readonly BigInteger SmallPrimesProduct = new BigInteger(new byte[]
    {
        0x81, 0x38, 0xe8, 0xa0, 0xfc, 0xf3, 0xa4, 0xe8, 0x4a, 0x77, 0x1d, 0x40, 0xfd, 0x30, 0x5d, 0x7f,
        0x4a, 0xa5, 0x93, 0x06, 0xd7, 0x25, 0x1d, 0xe5, 0x4d, 0x98, 0xaf, 0x8f, 0xe9, 0x57, 0x29, 0xa1,
        0xf7, 0x3d, 0x89, 0x3f, 0xa4, 0x24, 0xcd, 0x2e, 0xdc, 0x86, 0x36, 0xa6, 0xc3, 0x28, 0x5e, 0x02,
        0x2b, 0x0e, 0x38, 0x66, 0xa5, 0x65, 0xae, 0x81, 0x08, 0xee, 0xd8, 0x59, 0x1c, 0xd4, 0xfe, 0x8d,
        0x2c, 0xe8, 0x61, 0x65, 0xa9, 0x78, 0xd7, 0x19, 0xeb, 0xf6, 0x47, 0xf3, 0x62, 0xd3, 0x3f, 0xca,
        0x29, 0xcd, 0x17, 0x9f, 0xb4, 0x24, 0x01, 0xcb, 0xaf, 0x3d, 0xf0, 0xc6, 0x14, 0x05, 0x6f, 0x9c,
        0x8f, 0x3c, 0xfd, 0x51, 0xe4, 0x74, 0xaf, 0xb6, 0xbc, 0x69, 0x74, 0xf7, 0x8d, 0xb8, 0xab, 0xa8,
        0xe9, 0xe5, 0x17, 0xfd, 0xed, 0x65, 0x85, 0x91, 0xab, 0x75, 0x02, 0xbd, 0x41, 0x84, 0x94, 0x62,
        0xf
    });
    
    private readonly BigInteger modulus;
    private readonly BigInteger exponent;
    
    private const int MaxBitLength = 16384;

    #endregion
    
    #region Constructors
    
    public RsaKey(
        bool isPrivate,
        BigInteger	modulus,
        BigInteger	exponent)
        : base(isPrivate)
    {
        
        if (exponent <= 0)
            throw new ArgumentException("RSA exponent must be positive", nameof(exponent));

        if (!isPrivate && exponent.IsEven)
            throw new ArgumentException("RSA public exponent must be odd", nameof(exponent));
        
        this.modulus = Validate(modulus);
        this.exponent = exponent;
        
    }
    
    #endregion
    
    #region Properties
    
    public BigInteger Modulus
    {
        get { return modulus; }
    }

    public BigInteger Exponent
    {
        get { return exponent; }
    }
    
    #endregion
    
    #region Methods

    private static BigInteger Validate(BigInteger modulus)
    {
        if (modulus <= 0)
            throw new ArgumentException("RSA modulus must be positive", nameof(modulus));

        if (modulus.IsEven)
            throw new ArgumentException("RSA modulus must be odd", nameof(modulus));
        
        if (modulus.GetBitLength() > MaxBitLength)
            throw new ArgumentException($"RSA modulus exceeds maximum size of {MaxBitLength} bits", nameof(modulus));

        if (HasSmallPrimeFactors(modulus))
            throw new ArgumentException("RSA modulus has small prime factors", nameof(modulus));
        
        return modulus;
    }
    
    private static bool HasSmallPrimeFactors(BigInteger modulus)
    {
        
        BigInteger larger = modulus.GetBitLength() >= SmallPrimesProduct.GetBitLength() 
            ? modulus 
            : SmallPrimesProduct;
        
        BigInteger smaller = larger == modulus ? SmallPrimesProduct : modulus;
    
        return BigInteger.GreatestCommonDivisor(larger,smaller) != BigInteger.One;
        
    }
    
    #endregion
    
    #region IEquatable implementation
    
    public bool Equals(RsaKey? other)
    {
        if (other is null) return false;
        
        return IsPrivate == other.IsPrivate &&
                   modulus == other.modulus &&
                   exponent == other.exponent;
        
    }

    public override bool Equals(object? obj) => Equals(obj as RsaKey);

    public override int GetHashCode() => HashCode.Combine(Modulus, Exponent, IsPrivate);
        
    #endregion
    
}