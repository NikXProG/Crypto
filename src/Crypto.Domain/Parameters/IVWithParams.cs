using Crypto.Domain.Interfaces;

namespace Crypto.Domain.Parameters;

public class IVWithParams : ICryptoParams
{
    
    #region Fields
    
    private readonly byte[] _iv;
    
    private readonly ICryptoParams _parameters;
    
    #endregion
    
    #region Constructors
    
    public IVWithParams(ICryptoParams parameters, byte[] iv)
    {
        _parameters = parameters;
        ArgumentNullException.ThrowIfNull(iv);
        
        _iv =  (byte[])iv.Clone();
    }
    
    #endregion
    
    #region Properties
    
    public int IVLength => _iv.Length;
    
    public byte[] IV => (byte[])_iv.Clone();
    
    public ICryptoParams InnerParameters => _parameters;
    
    #endregion
    
    #region Methods

    public void WriteIVTo(byte[] buf, int off, int len)
    {
        ArgumentNullException.ThrowIfNull(buf);
        
        int available = buf.Length - off;
        
        if ((off | available) < 0)
            throw new ArgumentOutOfRangeException(nameof(off));
    
        if ((len | available - len) < 0 || _iv.Length != len)
            throw new ArgumentOutOfRangeException(nameof(len));

        Array.Copy(_iv, 0, buf, off, len);
        
    }
    
    #endregion
    
}