
using Crypto.Core;

namespace Crypto.Symmetrical.Parameters;

public class SymmetricalParameters
{
    
    public SymmetricalParameters(
        int keySize,
        int blockSize,
        int feedbackSize, 
        CipherMode mode,
        PaddingMode padding,
        byte[] key,
        byte[] iv)
    {
        IV = iv;
        KeySize = keySize;
        BlockSize = blockSize;
        FeedbackSize = feedbackSize;
        Mode = mode;
        Padding = padding;
        Key = key;
    }
    
    public byte[] IV
    {
        get;
        set;
    }

    public byte[] Key
    {
        get; 
        set;
    }

    public int KeySize
    {
        get;
        set;
    }

    public CipherMode Mode
    {
        get;
        set;
    }

    public  int BlockSize
    {
        get; 
        set;
    }

    public  int FeedbackSize
    {
        get;
        set;
    }

    public  PaddingMode Padding
    {
        get;
        set;
    }
    
}
