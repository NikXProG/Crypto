namespace Crypto.Domain.Interfaces;

public interface ICryptable
{
    
    byte[] Encrypt(byte[] plaintext);
    
    byte[] Decrypt(byte[] ciphertext);
    
}