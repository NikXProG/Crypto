namespace Crypto.Parameters;

internal class AesGaloisField
{
    internal const uint m1 = 0x80808080;
    internal const uint m2 = 0x7f7f7f7f;
    internal const uint m3 = 0x0000001b;
    internal const uint m4 = 0xC0C0C0C0;
    internal const uint m5 = 0x3f3f3f3f;

    internal static uint InverseMixColumn(uint x)
    {
        uint t0, t1;
        t0 = x;
        t1 = t0 ^ Shift(t0, 8);
        t0 ^= MultiplyByX(t1);
        t1 ^= MultiplyByX2(t0);
        t0 ^= t1 ^ Shift(t1, 16);
        return t0;
    }

    internal static uint Shift(uint r, int shift) => 
        (r >> shift) | (r << (32 - shift));
    
    
    internal static uint MultiplyByX(uint x) => 
        ((x & m2) << 1) ^ (((x & m1) >> 7) * m3);

    internal static uint MultiplyByX2(uint x)
    {
        uint t0 = (x & m5) << 2;
        uint t1 = (x & m4);
        t1 ^= (t1 >> 1);
        return t0 ^ (t1 >> 2) ^ (t1 >> 5);
    }
       
}