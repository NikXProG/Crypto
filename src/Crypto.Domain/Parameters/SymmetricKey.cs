using Crypto.Domain.Interfaces;

namespace Crypto.Domain.Parameters;

public class SymmetricKey : ICryptoParams
{
    
    private  readonly byte[] _key;
    
    public SymmetricKey(byte[] key)
    {
        ArgumentNullException.ThrowIfNull(key);

        _key = (byte[])key.Clone();
    }
    
    public byte[] GetKey()
    {
        return (byte[])_key.Clone();
    }
    
    public int KeyLength => _key.Length;
    
}