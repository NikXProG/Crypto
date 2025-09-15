namespace Crypto.Core.Interfaces;

public interface ICryptable
{
    
    byte[] Encrypt(byte[] plaintext);
    
    byte[] Decrypt(byte[] ciphertext);
    
}