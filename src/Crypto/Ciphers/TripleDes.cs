using Crypto.Core;
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

    public byte[] Decrypt(byte[] ciphertext)
    {
        throw new NotImplementedException();
    }

    public byte[] Key { get; set; }

    public string AlgorithmName { get; }

    public byte[] Encrypt(byte[] plaintext)
    {
        throw new NotImplementedException();
    }

    public byte[] IV { get; set; }

    public int BlockSize { get; set; }

    public ValidRangeSize[] KeyValidRanges { get; }
    
    public ValidRangeSize[] IVValidRanges { get; }

    public int KeySize { get; set; }

    public CipherMode Mode { get; set; }

    public int FeedbackSize { get; set; }

    public PaddingMode Padding { get; set; }

    public ValidRangeSize[] BlockValidRanges { get; }

    public IDecryptor CreateDecryptor()
    {
        throw new NotImplementedException();
    }

    public IEncryptor CreateEncryptor()
    {
        throw new NotImplementedException();
    }
    
    
}