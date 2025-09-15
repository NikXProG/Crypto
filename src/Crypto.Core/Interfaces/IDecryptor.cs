namespace Crypto.Core.Interfaces;

public interface IDecryptor
{
    int DecryptBlock(
        byte[] inputBuffer,
        int inputOffset,
        int inputCount,
        byte[] outputBuffer,
        int outputOffset);
  
    byte[] DecryptFinalBlock(
        byte[] inputBuffer,
        int inputOffset, 
        int inputCount);

}