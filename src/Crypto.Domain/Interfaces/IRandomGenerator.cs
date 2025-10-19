namespace Crypto.Domain.Interfaces;

public interface IRandomGenerator
{
    void NextBytes(byte[] bytes);

    void NextBytes(byte[] bytes, int start, int len);
    
    byte[] GenerateArrayBytes(int length);
    
}