namespace Crypto.Core
{
    
    public enum CipherMode
    {
        CBC = 1, // Sequential encryption. Error in ciphertext corrupts two blocks. (Requires padding)
    
        PCBC = 2, // Error in ciphertext propagates to all following blocks, ensuring total corruption on tampering.
    
        CFB = 3, // Stream cipher mode. Self-recovering from sync errors. No padding needed.
    
        OFB = 4, // Stream cipher mode. Zero error propagation. Critical: NEVER reuse IV/key pair.
   
        ECB = 5, // PARALLEL. INSECURE: Reveals patterns (identical plaintext blocks -> identical ciphertext blocks).
    
        CTR = 6, // PARALLEL. Efficient, no padding. Critical: NEVER reuse counter value/key pair.
    
        CTRD = 7 // PARALLEL. CTR with custom counter step (D - delta). 
        
    }
}
