namespace Crypto.Domain.Interfaces;

public interface IEncryptParamSetup
{
    void Setup(bool encrypting, ICryptoParams cryptoParams);
    
}