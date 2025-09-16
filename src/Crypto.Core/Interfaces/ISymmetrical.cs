namespace Crypto.Core.Interfaces
{
    
    public interface ISymmetrical : ICryptoTransform, ICryptable
    {

        string AlgorithmName
        {
            get;
        }

        byte[] Key
        {
            get;
            set;
        }

        int KeySize
        {
            get;
            set;
        }

        byte[] IV
        {
            get;
            set;
        }

        int BlockSize
        {
            get; 
            set;
        }

        PaddingMode Padding
        {
            get;
            set;
        }

        CipherMode Mode
        {
            get;
            set;
        }

        int FeedbackSize
        {
            get;
            set;
        }

        ValidRangeSize[] KeyValidRanges
        {
            get;
        }

        ValidRangeSize[] BlockValidRanges
        {
            get;
        }
      
        
    }
    
}



