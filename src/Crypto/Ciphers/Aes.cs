using Crypto.Core.Interfaces;

namespace Crypto.Symmetrical.Algorithms
{
    
    public abstract class Aes
    {
        
        public string AlgorithmName => "AES (Rijndael)";

        public void GenerateIV()
        {
            throw new NotImplementedException();
        }

        public void GenerateKey()
        {
            throw new NotImplementedException();
        }

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
}

