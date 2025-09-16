namespace Crypto.Core.Interfaces;

public interface ICryptoTransform
{
    
    IEncryptor CreateEncryptor();
        
    IDecryptor CreateDecryptor();
    
}