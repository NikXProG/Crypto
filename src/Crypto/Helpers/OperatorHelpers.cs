namespace Crypto.Helpers;

internal static class OperatorHelpers 
{
    internal static int GetFullBlocksSize(int totalSize, int blockSize)
    {
        if (totalSize < 0)
            return 0;

        int blockSizeMask = blockSize - 1;
        if ((blockSize & blockSizeMask) == 0)
            return totalSize & ~blockSizeMask;

        return totalSize - totalSize % blockSize;
        
    }
    
}