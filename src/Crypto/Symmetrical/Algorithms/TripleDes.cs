using Crypto.Core.Interfaces;

namespace Crypto.Symmetrical.Algorithms;

public class TripleDes : ISymmetrical {
    
    
    public void GenerateIV()
    {
        throw new NotImplementedException();
    }

    public void GenerateKey()
    {
        throw new NotImplementedException();
    }

    public string AlgorithmName => "TripleDES";

    public IDecryptor GetDecryptor()
    {
        throw new NotImplementedException();
    }

    public IEncryptor GetEncryptor()
    {
        throw new NotImplementedException();
    }

    public byte[] Encrypt(byte[] plaintext)
    {
        throw new NotImplementedException();
    }

    public byte[] Decrypt(byte[] ciphertext)
    {
        throw new NotImplementedException();
    }
}