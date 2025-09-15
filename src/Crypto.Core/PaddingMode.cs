namespace Crypto.Core;

public enum PaddingMode
{
    None = 1,      // No padding applied
    
    Zeros = 2,     // Pad with zero bytes
    
    PKCS7 = 3,     // Pad with bytes each equal to padding length
    
    ANSIX923 = 4,  // Pad with zeros plus last byte as padding length
    
    ISO10126 = 5,  // Pad with random bytes plus last byte as padding length
}