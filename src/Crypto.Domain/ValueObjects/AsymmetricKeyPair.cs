using Crypto.Domain.Parameters;

namespace Crypto.Domain.ValueObjects;

public class AsymmetricKeyPair
{
    private readonly AsymmetricKey _publicKey;
    private readonly AsymmetricKey _privateKey;
    
    public AsymmetricKeyPair(
        AsymmetricKey publicKey,
        AsymmetricKey privateKey)
    {
        if (publicKey.IsPrivate)
            throw new ArgumentException("Expected a public key", nameof(publicKey));
        if (!privateKey.IsPrivate)
            throw new ArgumentException("Expected a private key", nameof(privateKey));

        this._publicKey = publicKey;
        this._privateKey = privateKey;
    }
    
    public AsymmetricKey Public => _publicKey;
    
    public AsymmetricKey Private => _privateKey;
    
}