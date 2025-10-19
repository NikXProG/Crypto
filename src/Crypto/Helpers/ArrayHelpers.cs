using System.Numerics;

namespace Crypto.Helpers;

internal static class ArrayHelpers
{
    
    internal static bool SegmentsOverlap(int aOff, int aLen, int bOff, int bLen)
    {
        return aLen > 0
               && bLen > 0
               && aOff - bOff < bLen
               && bOff - aOff < aLen;
    }
    
    internal static byte[] CopyOf(byte[] data, int newLength)
    {
        byte[] tmp = new byte[newLength];
        Array.Copy(data, 0, tmp, 0, System.Math.Min(newLength, data.Length));
        return tmp;
    }

    internal static void ValidateBuffer<T>(T[] buf)
    {
        if (buf == null)
            throw new ArgumentNullException(nameof(buf));
    }
    
    internal static void ValidateSegment<T>(T[] buf, int off, int len)
    {
        if (buf == null)
            throw new ArgumentNullException(nameof(buf));
        int available = buf.Length - off;
        if ((off | available) < 0)
            throw new ArgumentOutOfRangeException(nameof(off));
        int remaining = available - len;
        if ((len | remaining) < 0)
            throw new ArgumentOutOfRangeException(nameof(len));
    }
    
    internal static void InternalCopyBufferToSegment<T>(T[] srcBuf, T[] dstBuf, int dstOff, int dstLen)
    {
        if (srcBuf.Length != dstLen)
            throw new ArgumentOutOfRangeException(nameof(dstLen));

        Array.Copy(srcBuf, 0, dstBuf, dstOff, dstLen);
    }
    
    internal static void CopyBufferToSegment<T>(T[] srcBuf, T[] dstBuf, int dstOff, int dstLen)
    {
        ValidateBuffer(srcBuf);
        ValidateSegment(dstBuf, dstOff, dstLen);
        InternalCopyBufferToSegment(srcBuf, dstBuf, dstOff, dstLen);
    }
    
    
}