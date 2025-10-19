namespace Crypto.Domain.Interfaces;

public interface IBlockCipherPadding
{
    int AddPadding(byte[] input, int inOff);
    
    int PadCount(byte[] input);
    
}