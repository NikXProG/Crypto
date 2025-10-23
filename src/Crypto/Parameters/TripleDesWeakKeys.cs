namespace Crypto.Parameters;

public class TripleDesWeakKeys
{
    
    
    public static bool IsWeakKey(byte[] key)
    {
        return IsWeakKey(key, 0, key.Length);
    }
    
    public static bool IsWeakKey(byte[] key, int offset)
    {
        return IsWeakKey(key, offset, key.Length - offset);
    }
    
    public static bool IsWeakKey(byte[] key, int offset, int length)
    {
        for (int i = offset; i < length; i += 8)
        {
            if (DesWeakKeys.IsWeakKey(key.AsSpan(i)))
                return true;
        }

        return false;
    }
    
    public static bool IsTripleKey(byte[] key)
    {
        return IsTripleKey(key, 0);
    }
    
    public static bool IsTripleKey(byte[] key, int offset)
    {
        return key.Length == 16 ? Is2Key(key, offset) : Is3Key(key, offset);
    }
    
    public static bool Is2Key(byte[] key, int offset)
    {
        bool isValid = false;
        for (int i = offset; i != offset + 8; i++)
        {
            isValid |= (key[i] != key[i + 8]);
        }
        return isValid;
    }
    
    public static bool Is3Key(byte[] key, int offset)
    {
        bool diff12 = false, diff13 = false, diff23 = false;
        for (int i = offset; i != offset + 8; i++)
        {
            diff12 |= (key[i] != key[i + 8]);
            diff13 |= (key[i] != key[i + 16]);
            diff23 |= (key[i + 8] != key[i + 16]);
        }
        return diff12 && diff13 && diff23;
    }
}