using Crypto.Domain.Interfaces;
using Crypto.Parameters;

namespace Crypto.Engines;

public class DesEngineCore : IDes
{
    public void DesFunc(int[] wKey, ref uint hi32, ref uint lo32)
        {
            uint left = hi32;
            uint right = lo32;
            uint work;

            work = ((left >> 4) ^ right) & 0x0f0f0f0f;
            right ^= work;
            left ^= (work << 4);
            work = ((left >> 16) ^ right) & 0x0000ffff;
            right ^= work;
            left ^= (work << 16);
            work = ((right >> 2) ^ left) & 0x33333333;
            left ^= work;
            right ^= (work << 2);
            work = ((right >> 8) ^ left) & 0x00ff00ff;
            left ^= work;
            right ^= (work << 8);
            right = (right << 1) | (right >> 31);
            work = (left ^ right) & 0xaaaaaaaa;
            left ^= work;
            right ^= work;
            left = (left << 1) | (left >> 31);

            for (int round = 0; round < 8; round++)
            {
                uint fval;

                work  = (right << 28) | (right >> 4);
                work ^= (uint)wKey[round * 4 + 0];
                fval  = DesTableCipher.SP7[work  & 0x3f];
                fval |= DesTableCipher.SP5[(work >>  8) & 0x3f];
                fval |= DesTableCipher.SP3[(work >> 16) & 0x3f];
                fval |= DesTableCipher.SP1[(work >> 24) & 0x3f];
                work  = right ^ (uint)wKey[round * 4 + 1];
                fval |= DesTableCipher.SP8[ work        & 0x3f];
                fval |= DesTableCipher.SP6[(work >>  8) & 0x3f];
                fval |= DesTableCipher.SP4[(work >> 16) & 0x3f];
                fval |= DesTableCipher.SP2[(work >> 24) & 0x3f];
                left ^= fval;
                work  = (left << 28) | (left >> 4);
                work ^= (uint)wKey[round * 4 + 2];
                fval  = DesTableCipher.SP7[ work        & 0x3f];
                fval |= DesTableCipher.SP5[(work >>  8) & 0x3f];
                fval |= DesTableCipher.SP3[(work >> 16) & 0x3f];
                fval |= DesTableCipher.SP1[(work >> 24) & 0x3f];
                work  = left ^ (uint)wKey[round * 4 + 3];
                fval |= DesTableCipher.SP8[ work        & 0x3f];
                fval |= DesTableCipher.SP6[(work >>  8) & 0x3f];
                fval |= DesTableCipher.SP4[(work >> 16) & 0x3f];
                fval |= DesTableCipher.SP2[(work >> 24) & 0x3f];
                right ^= fval;
            }

            right = (right << 31) | (right >> 1);
            work = (left ^ right) & 0xaaaaaaaa;
            left ^= work;
            right ^= work;
            left = (left << 31) | (left >> 1);
            work = ((left >> 8) ^ right) & 0x00ff00ff;
            right ^= work;
            left ^= (work << 8);
            work = ((left >> 2) ^ right) & 0x33333333;
            right ^= work;
            left ^= (work << 2);
            work = ((right >> 16) ^ left) & 0x0000ffff;
            left ^= work;
            right ^= (work << 16);
            work = ((right >> 4) ^ left) & 0x0f0f0f0f;
            left ^= work;
            right ^= (work << 4);

            hi32 = right;
            lo32 = left;
        }

    public int[] TransformKey(bool encrypting, byte[] key)
    {
        int[] newKey = new int[32];
        bool[] pc1m = new bool[56];
		bool[] pcr = new bool[56];

		for (int j = 0; j < 56; j++ )
        {
            int l = DesTableCipher.pc1[j];

			pc1m[j] = ((key[(uint) l >> 3] & DesTableCipher.bytebit[l & 07]) != 0);
        }

        for (int i = 0; i < 16; i++)
        {
            int l, m, n;

            if (encrypting)
            {
                m = i << 1;
            }
            else
            {
                m = (15 - i) << 1;
            }

            n = m + 1;
            newKey[m] = newKey[n] = 0;

            for (int j = 0; j < 28; j++)
            {
                l = j + DesTableCipher.totrot[i];
                if ( l < 28 )
                {
                    pcr[j] = pc1m[l];
                }
                else
                {
                    pcr[j] = pc1m[l - 28];
                }
            }

            for (int j = 28; j < 56; j++)
            {
                l = j + DesTableCipher.totrot[i];
                if (l < 56 )
                {
                    pcr[j] = pc1m[l];
                }
                else
                {
                    pcr[j] = pc1m[l - 28];
                }
            }

            for (int j = 0; j < 24; j++)
            {
                if (pcr[DesTableCipher.pc2[j]])
                {
                    newKey[m] |= DesTableCipher.bigbyte[j];
                }

                if (pcr[DesTableCipher.pc2[j + 24]])
                {
                    newKey[n] |= DesTableCipher.bigbyte[j];
                }
            }
        }

        //
        // store the processed key
        //
        for (int i = 0; i != 32; i += 2)
        {
            int i1, i2;

            i1 = newKey[i];
            i2 = newKey[i + 1];

            newKey[i] = (int) ( (uint) ((i1 & 0x00fc0000) << 6)  |
                                (uint) ((i1 & 0x00000fc0) << 10) |
                                ((uint) (i2 & 0x00fc0000) >> 10) |
                                ((uint) (i2 & 0x00000fc0) >> 6));

            newKey[i + 1] = (int) ( (uint) ((i1 & 0x0003f000) << 12) |
                                    (uint) ((i1 & 0x0000003f) << 16) |
                                    ((uint) (i2 & 0x0003f000) >> 4) |
                                    (uint) (i2 & 0x0000003f));
        }

        return newKey;
    }
    
}