namespace Crypto.Core.Extensions
{
    public static class ByteExtensions
    {
    
        public static byte[]? CloneByteArray(this byte[]? src)
        {
            return src switch
            {
                null => null,
                { Length: 0 } => src,
                _ => (byte[])src.Clone(),
            };
        }
    
        
        public static byte[] EnsureOddParity(this byte[] key)
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

        public static byte[] Concat(this byte[] first, byte[] second)
        {
            byte[] result = new byte[first.Length + second.Length];
            Buffer.BlockCopy(first, 0, result, 0, first.Length);
            Buffer.BlockCopy(second, 0, result, first.Length, second.Length);
            return result;
        }

        public static byte[] Concat(this byte[] first, byte second)
        {
            byte[] result = new byte[first.Length + 1];
            Buffer.BlockCopy(first, 0, result, 0, first.Length);
            result[first.Length] = second;
            return result;
        }
        
    }
}
