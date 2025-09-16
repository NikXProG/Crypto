namespace Crypto.Core;

public sealed class ValidRangeSize
{
    
    public ValidRangeSize(int minSize, int maxSize, int stepSize)
    {
        MinSize = minSize;
        MaxSize = maxSize;
        StepSize = stepSize;
    }

    public int MinSize { get; }
    public int MaxSize { get; }
    
    /// <summary>
    /// shows how much you need to deviate
    /// from min size so that the next key value is valid
    /// </summary>
    public int StepSize { get; }
    
}