using Crypto.Domain.Interfaces;
using Crypto.Domain.Parameters;

namespace Crypto.Extensions;

public static class AsymmetricCipherExtensions
{
    
    #region Encrypt
    
    public static byte[] Encrypt(
        this IAsymmetricalCipher cipher,
        AsymmetricKey key,
        byte[] plaintext)
    {

        if (key.IsPrivate)
        {
            throw new ArgumentException("The key must be a public key for encrypt.", nameof(key));
        }
            
        cipher.Setup(true, key);
            
        return cipher.ProcessBlock(plaintext, 0, plaintext.Length);
           
    }
    
    #endregion
    
    #region Decrypt
    
    public static byte[] Decrypt(
        this IAsymmetricalCipher cipher,
        AsymmetricKey key,
        byte[] plaintext)
    {

        if (!key.IsPrivate)
        {
            throw new ArgumentException("The key must be a private key for decrypt.", nameof(key));
        }
            
        cipher.Setup(false, key);
            
        return cipher.ProcessBlock(plaintext, 0, plaintext.Length);
           
    }

    #endregion
    
}