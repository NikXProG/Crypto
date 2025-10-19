using Crypto.Domain.Interfaces;

namespace Crypto.Domain.Parameters;

public class AsymmetricKey : ICryptoParams, IEquatable<AsymmetricKey>
{
    
    private readonly bool _isPrivateKey;
    
    protected AsymmetricKey(
        bool privateKey)
    {
        this._isPrivateKey = privateKey;
    }
    
    public bool IsPrivate
    {
        get { return _isPrivateKey; }
    }
    
    public static bool operator ==(AsymmetricKey key1, AsymmetricKey key2)
    {
        if (key1 is null)
        {
            return key2 is null;
        }

        return key1.Equals(key2);
    }
    
    public static bool operator !=(AsymmetricKey key1, AsymmetricKey key2)
    {
        if (key1 is null)
        {
            return key2 is not null;
        }

        return !key1.Equals(key2);
    }

    public override bool Equals(object? obj) => Equals(obj as AsymmetricKey);
    public bool Equals(AsymmetricKey? other) => other != null && _isPrivateKey == other._isPrivateKey;
    
    public override int GetHashCode() => _isPrivateKey.GetHashCode();
    
}