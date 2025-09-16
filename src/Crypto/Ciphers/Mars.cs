using Crypto.Core.Interfaces;

namespace Crypto.Symmetrical.Algorithms;

public class Mars
{
    
    public string AlgorithmName => "Mars";

    public Mars()
    {
        
    }

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

    public byte[] Encrypt(byte[] key)
    {
        throw new NotImplementedException();
    }

    public byte[] Decrypt(byte[] key)
    {
        throw new NotImplementedException();
    }
}