namespace Crypto.Core.Interfaces
{
    
    public interface IBlockCipher
    {
    
        public int ProcessBlock(
            ReadOnlySpan<byte> input,
            Span<byte> output);

        public int ProcessBlockFinal(
            ReadOnlySpan<byte> input,
            Span<byte> output);
    
    }
}
