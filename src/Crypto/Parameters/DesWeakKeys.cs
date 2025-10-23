using System.Buffers.Binary;
using Crypto.Helpers;

namespace Crypto.Parameters;

internal static class DesWeakKeys
{
    
    #region Properties
    
    public static IReadOnlySet<ulong> WeakKeys { get; } = new HashSet<ulong>
    {
        0x0101010101010101,
        0xfefefefefefefefe,
        0x1f1f1f1f0e0e0e0e, 
        0xe0e0e0e0f1f1f1f1
    };
    
    public static IReadOnlySet<ulong> SemiWeakKeys { get; } = new HashSet<ulong>
    {
        0x01fe01fe01fe01fe, 0xfe01fe01fe01fe01, 0x1fe01fe00ef10ef1,
        0xe01fe01ff10ef10e, 0x01e001e001f101f1, 0xe001e001f101f101,
        0x1ffe1ffe0efe0efe, 0xfe1ffe1ffe0efe0e, 0x011f011f010e010e,
        0x1f011f010e010e01, 0xe0fee0fef1fef1fe, 0xfee0fee0fef1fef1
    };
    
    public static IReadOnlySet<ulong> AllWeakKeys { get; } = 
        WeakKeys.Union(SemiWeakKeys).ToHashSet();
    
    public static bool IsWeakKey(byte[] key)
    {
        return key != null && IsWeakKey(key.AsSpan(0));
    }
    
    public static bool IsWeakKey(ReadOnlySpan<byte> key)
    {
        if (key.Length != 8)
            return false;
    
        return AllWeakKeys.Contains(GetNormalizedKey(key));
    }
    
    private static ulong GetNormalizedKey(ReadOnlySpan<byte> key) =>
        BinaryPrimitives.ReadUInt64BigEndian(key.EnsureOddParity());

    
    #endregion
    
}