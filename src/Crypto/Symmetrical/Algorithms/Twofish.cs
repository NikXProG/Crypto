using Crypto.Core.Interfaces;

namespace Crypto.Symmetrical.Algorithms;

public class Twofish : ISymmetrical
{
    public string AlgorithmName => "Twofish";
    
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

    public byte[] Decrypt(byte[] ciphertext)
    {
        throw new NotImplementedException();
    }

    public byte[] Encrypt(byte[] ciphertext)
    {
        throw new NotImplementedException();
    }
}