using System.Numerics;
using Crypto.Domain.Exceptions;
using Crypto.Domain.Interfaces;
using Crypto.Domain.Parameters;
using Crypto.Helpers;

namespace Crypto.Engines;

public class RsaEngine : IAsymmetricalCipher
{
    
    #region Fields

    private bool _encrypting;

    private RsaKey _key;
    
    private int _bitModulusLength;
    
    #endregion

    #region Properties

    public int OutputBlockSize
    {
        get
        {
            ArgumentNullException.ThrowIfNull(_key);
            return _encrypting ? 
                (_bitModulusLength + 7) / 8  : 
                (_bitModulusLength - 1) / 8;
        }
    }

    public int InputBlockSize
    {
        get
        {
            ArgumentNullException.ThrowIfNull(_key);
            return _encrypting ?
                (_bitModulusLength - 1) / 8 : 
                (_bitModulusLength + 7) / 8;
        }
    }
    
    #endregion

    #region Methods
    
    public void Setup(bool encrypting, ICryptoParams cryptoParams)
    {
        _key = cryptoParams as RsaKey ?? throw new ParameterKeyException("Not an RSA key");
        
        _encrypting = encrypting;
        
        _bitModulusLength = (int)_key.Modulus.GetBitLength(); 
    }
    
    
    public byte[] ProcessBlock(byte[] inBuf, int inOff, int inLen)
    {
        ArgumentNullException.ThrowIfNull(_key);
        
        BigInteger input = new BigInteger(inBuf.AsSpan(inOff, inLen), isUnsigned: true);

        if (input >= _key.Modulus)
        {
            throw new ParameterLengthException("input too large for RSA cipher");
        }
        
        BigInteger output = ProcessBlock(input);
        return output.ToByteArray(true);
    }
    
    private BigInteger ProcessBlock(BigInteger input)
    {
    
        if (_key is not RsaCrtKey crt)
            return input.ModExp(_key.Exponent, _key.Modulus);
        
        BigInteger p = crt.P;
        BigInteger q = crt.Q;
        BigInteger dP = crt.DP;
        BigInteger dQ = crt.DQ;
        BigInteger qInv = crt.QInv;
    
        // mP = ((input Mod p) ^ dP)) Mod p
        BigInteger mP = (input % p).ModExp(dP, p);

        // mQ = ((input Mod q) ^ dQ)) Mod q
        BigInteger mQ =  (input % q).ModExp(dQ, q);

        // h = qInv * (mP - mQ) Mod p
        BigInteger h = (qInv * (mP - mQ)) % p;
        
        // m = h * q + mQ
        BigInteger m = mQ + h * q;
        
        BigInteger check = m.ModExp(crt.PublicExponent, crt.Modulus);
        
        if (!check.Equals(input))
            throw new InvalidOperationException("RSA engine faulty decryption/signing detected");

        return m;
    }
    
    #endregion
    
}