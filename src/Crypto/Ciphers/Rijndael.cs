using Crypto.Core.Interfaces;

namespace Crypto.Symmetrical.Algorithms;

public class Rijndael 
{
    public string AlgorithmName => "Rijndael";
    
    public IDecryptor GetDecryptor()
    {
        throw new NotImplementedException();
    }

    public IEncryptor GetEncryptor()
    {
        throw new NotImplementedException();
    }

    public void GenerateIV()
    {
        throw new NotImplementedException();
    }

    public void GenerateKey()
    {
        throw new NotImplementedException();
    }

    public byte[] Encrypt(byte[] plain)
    {
        throw new NotImplementedException();
    }

    public byte[] Decrypt(byte[] ciphertext)
    {
        throw new NotImplementedException();
    }
}
