namespace Crypto.Domain.Enums;

public enum BlockPadding
{
    None = 1,      // No blockPadding applied
    
    Zeros = 2,     // Pad with zero bytes
    
    PKCS7 = 3,     // Pad with bytes each equal to blockPadding length
    
    ANSIX923 = 4,  // Pad with zeros plus last byte as blockPadding length
    
    ISO10126 = 5,  // Pad with random bytes plus last byte as blockPadding length
}