namespace Crypto.Core.Interfaces;

public interface IBlockCipherPadding
{
    
    int CalculatePaddedLength(
        int plaintextLength,
        int paddingSizeInBytes);

    int ApplyPadding(
        ReadOnlySpan<byte> block,
        Span<byte> destination,
        int paddingSizeInBytes);
    
     bool IsAutoDepaddingSupported();

     int ValidateAndRemovePadding(
         ReadOnlySpan<byte> block,
         int blockSize);

}