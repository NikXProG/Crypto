namespace Crypto.Core.Interfaces;

public interface IEncryptor
{
    int EncryptBlock(
        byte[] inputBuffer,
        int inputOffset,
        int inputCount,
        byte[] outputBuffer,
        int outputOffset);
  
    byte[] EncryptFinalBlock(
        byte[] inputBuffer,
        int inputOffset, 
        int inputCount);
    
}