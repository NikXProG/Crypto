using System.Numerics;
using Crypto.Domain.Interfaces;
using Crypto.Domain.ValueObjects;

namespace Crypto.Domain.Parameters;

public class RsaGeneratorParams : ICryptoParams
{
    
    #region Fields
    
    private readonly BigInteger _publicExponent;
    private readonly int _certainty;
    
    #endregion
    
    #region Properties

    public RsaGeneratorParams(
        BigInteger publicExponent,
        int certainty)
    {
        _publicExponent = publicExponent;
        _certainty = certainty;
    }
    
    #endregion
    
    #region Properties
    
    public BigInteger PublicExponent => _publicExponent;

    public int Certainty => _certainty;

    #endregion


}