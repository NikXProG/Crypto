namespace Crypto.Core.Interfaces;

public interface IBlockCipherTransform
{
    
    int ProcessBlock(
        byte[] inputBuffer,
        int inputOffset,
        int inputCount,
        byte[] outputBuffer,
        int outputOffset);
  
    byte[] ProcessFinalBlock(
        byte[] inputBuffer,
        int inputOffset, 
        int inputCount);
    
    
    // int InputBlockSize
    // {
    //     get;
    // }
    //
    // int OutputBlockSize
    // {
    //     get;
    // }
    //
    // bool CanTransformMultipleBlocks
    // {
    //     get;
    // }
    //
    // bool CanReuseTransform
    // {
    //     get;
    // }
    
}
