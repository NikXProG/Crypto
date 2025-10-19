using Crypto.Domain.Enums;
using Crypto.Domain.ValueObjects;

namespace Crypto.Domain.Interfaces
{
    
    public interface ISymmetricalProvider : ICryptable
    {

        byte[] Key
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

        BlockPadding BlockPadding
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



