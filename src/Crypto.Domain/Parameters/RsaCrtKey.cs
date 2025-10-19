using System.Numerics;

namespace Crypto.Domain.Parameters;

public class RsaCrtKey : RsaKey
{
    private readonly BigInteger _e, _p, _q, _dP, _dQ, _qInv;
    
    public RsaCrtKey(
        BigInteger	modulus,
        BigInteger publicExponent,
        BigInteger privateExponent,
        BigInteger p,
        BigInteger q,
        BigInteger dP,
        BigInteger dQ,
        BigInteger qInv)
        : base(true, modulus, privateExponent)
    {
        
        CheckSignValue(publicExponent, "publicExponent", "exponent");
        CheckSignValue(p, "p", "P value");
        CheckSignValue(q, "q", "Q value");
        CheckSignValue(dP, "dP", "DP value");
        CheckSignValue(dQ, "dQ", "DQ value");
        CheckSignValue(qInv, "qInv", "InverseQ value");
        
        _e = publicExponent;
        _p = p;
        _q = q;
        _dP = dP;
        _dQ = dQ;
        _qInv = qInv;
        
    }
    
    public BigInteger PublicExponent => _e;
    public BigInteger P => _p;
    public BigInteger Q => _q;
    public BigInteger DP => _dP;
    public BigInteger DQ => _dQ;
    public BigInteger QInv => _qInv;

    private static void CheckSignValue(BigInteger x, string name, string desc)
    {
     
        if (x.Sign <= 0)
            throw new ArgumentException("Not a valid RSA " + desc, name);
    }
    
    
    #region IEquatable implementation
    
    public bool Equals(RsaCrtKey? other)
    {
        if (other is null) return false;
        
        return  other.DP == _dP
                && other.DQ == _dQ
                && other.Exponent == Exponent
                && other.Modulus == Modulus
                && other.P == _p
                && other.Q == _q
                && other.PublicExponent == _e
                && other.QInv == _qInv;
        
    }

    public override bool Equals(object? obj) => Equals(obj as RsaCrtKey);
    
    public override int GetHashCode()
    {
        return DP.GetHashCode() ^ DQ.GetHashCode() ^ Exponent.GetHashCode() ^ Modulus.GetHashCode()
               ^ P.GetHashCode() ^ Q.GetHashCode() ^ PublicExponent.GetHashCode() ^ QInv.GetHashCode();
    }
    
    #endregion
    
}