using System.Buffers.Binary;
using System.Numerics;

namespace Crypto.Helpers
{
    internal static class ByteHelpers
    {
    
        internal static byte[]? CloneByteArray(this byte[]? src)
        {
            return src switch
            {
                null => null,
                { Length: 0 } => src,
                _ => (byte[])src.Clone(),
            };
        }
        
        internal static byte[] EnsureOddParity(this byte[] key)
        {
            var oddParityKey = new byte[key.Length];
            for (int index = 0; index < key.Length; index++)
            {
                // get last bit of each block
                oddParityKey[index] = (byte)(key[index] & 0xfe);

                // count the parity of the prev bits
                byte tmp1 = (byte)((oddParityKey[index] & 0xF) ^ (oddParityKey[index] >> 4));
                byte tmp2 = (byte)((tmp1 & 0x3) ^ (tmp1 >> 2));
                byte sumBitsMod2 = (byte)((tmp2 & 0x1) ^ (tmp2 >> 1));

                // If count of 1 will be parity
                // then we add 1 
                if (sumBitsMod2 == 0)
                    oddParityKey[index] |= 1;
            }
            return oddParityKey;
        }

        internal static uint ToUInt32(this byte[] bs, int offset)
        {
            return BinaryPrimitives.ReadUInt32BigEndian(bs.AsSpan(offset));
        }
        
        internal static uint ToUInt32(this ReadOnlySpan<byte> bs)
        {
            return BinaryPrimitives.ReadUInt32BigEndian(bs);
        }

        internal static void ToRawByte(this uint n, byte[] bs, int off)
        {
            BinaryPrimitives.WriteUInt32BigEndian(bs.AsSpan(off), n);
        }
        
        internal static void ToRawByte(this uint n, Span<byte> saveBuffer)
        {
            BinaryPrimitives.WriteUInt32BigEndian(saveBuffer, n);
        }
    }
}