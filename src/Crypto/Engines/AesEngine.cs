
using System.Security.Cryptography;
using Crypto.Domain.Exceptions;
using Crypto.Domain.Interfaces;
using Crypto.Domain.Parameters;
using Crypto.Domain.ValueObjects;
using Crypto.Helpers;
using Crypto.Parameters;
using Crypto.Utils;

namespace Crypto.Engines;

public class AesEngine : IBlockCipher
{
    
    #region Fields

    private const int BlockSize = 16;

    private int _rounds;
    private uint[][] _key;
    private bool _encrypting;

    #endregion

    #region Properties

    public int BlockSizeInBytes => BlockSize;

    #endregion

    #region Methods

    #region Public Methods

    public void Setup(bool encrypting, ICryptoParams cryptoParams)
    {
        if (cryptoParams is not SymmetricKey key)
        {
            throw new ArgumentException($"{nameof(cryptoParams)} must be of type {nameof(SymmetricKey)}.");
        }

        _encrypting = encrypting;
        _key = GenerateWorkingKey(encrypting, key.GetKey());
    }

    public int ProcessBlock(byte[] inBuf, int inOff, byte[] outBuf, int outOff)
    {
        return ProcessBlock(inBuf.AsSpan(inOff), outBuf.AsSpan(outOff));
    }

    public int ProcessBlock(ReadOnlySpan<byte> input, Span<byte> output)
    {
        if (_key == null)
        {
            throw new InvalidOperationException("AES engine - key not initialized");
        }
        
        Guard.ValidLength(input, BlockSize, "input buffer too short");
        Guard.ValidLength(output, BlockSize, "output buffer too short");

        return _encrypting ? EncryptBlock(input, output, _key) : DecryptBlock(input, output, _key);
    }

    #endregion

    #region Private Methods

    private uint SubWord(uint x)
    {
        return (uint)AesTableCipher.S[x & 255] |
               (((uint)AesTableCipher.S[(x >> 8) & 255]) << 8) |
               (((uint)AesTableCipher.S[(x >> 16) & 255]) << 16) |
               (((uint)AesTableCipher.S[(x >> 24) & 255]) << 24);
    }

    public uint[][] GenerateWorkingKey(bool encrypting, byte[] key)
    {
        int keyLen = key.Length;
        if (keyLen < 16 || keyLen > 32 || (keyLen & 7) != 0)
            throw new ArgumentException("Key length not 128/192/256 bits.");

        int KC = keyLen >> 2;
        this._rounds = KC + 6;

        uint[][] W = new uint[_rounds + 1][];
        for (int i = 0; i <= _rounds; ++i)
        {
            W[i] = new uint[4];
        }

        switch (KC)
        {
            case 4:
            {
                uint t0 = key.ToUInt32(0);
                W[0][0] = t0;
                uint t1 = key.ToUInt32(4);
                W[0][1] = t1;
                uint t2 = key.ToUInt32(8);
                W[0][2] = t2;
                uint t3 = key.ToUInt32(12);
                W[0][3] = t3;

                for (int i = 1; i <= 10; ++i)
                {
                    uint u = SubWord(AesGaloisField.Shift(t3, 8)) ^ AesTableCipher.rcon[i - 1];
                    t0 ^= u;
                    W[i][0] = t0;
                    t1 ^= t0;
                    W[i][1] = t1;
                    t2 ^= t1;
                    W[i][2] = t2;
                    t3 ^= t2;
                    W[i][3] = t3;
                }
                break;
            }
            case 6:
            {
                uint t0 = key.ToUInt32(0);
                W[0][0] = t0;
                uint t1 = key.ToUInt32(4);
                W[0][1] = t1;
                uint t2 = key.ToUInt32(8);
                W[0][2] = t2;
                uint t3 = key.ToUInt32(12);
                W[0][3] = t3;
                uint t4 = key.ToUInt32(16);
                W[1][0] = t4;
                uint t5 = key.ToUInt32(20);
                W[1][1] = t5;

                uint rcon = 1;
                uint u = SubWord(AesGaloisField.Shift(t5, 8)) ^ rcon;
                rcon <<= 1;
                t0 ^= u;
                W[1][2] = t0;
                t1 ^= t0;
                W[1][3] = t1;
                t2 ^= t1;
                W[2][0] = t2;
                t3 ^= t2;
                W[2][1] = t3;
                t4 ^= t3;
                W[2][2] = t4;
                t5 ^= t4;
                W[2][3] = t5;

                for (int i = 3; i < 12; i += 3)
                {
                    u = SubWord(AesGaloisField.Shift(t5, 8)) ^ rcon;
                    rcon <<= 1;
                    t0 ^= u;
                    W[i][0] = t0;
                    t1 ^= t0;
                    W[i][1] = t1;
                    t2 ^= t1;
                    W[i][2] = t2;
                    t3 ^= t2;
                    W[i][3] = t3;
                    t4 ^= t3;
                    W[i + 1][0] = t4;
                    t5 ^= t4;
                    W[i + 1][1] = t5;
                    u = SubWord(AesGaloisField.Shift(t5, 8)) ^ rcon;
                    rcon <<= 1;
                    t0 ^= u;
                    W[i + 1][2] = t0;
                    t1 ^= t0;
                    W[i + 1][3] = t1;
                    t2 ^= t1;
                    W[i + 2][0] = t2;
                    t3 ^= t2;
                    W[i + 2][1] = t3;
                    t4 ^= t3;
                    W[i + 2][2] = t4;
                    t5 ^= t4;
                    W[i + 2][3] = t5;
                }

                u = SubWord(AesGaloisField.Shift(t5, 8)) ^ rcon;
                t0 ^= u;
                W[12][0] = t0;
                t1 ^= t0;
                W[12][1] = t1;
                t2 ^= t1;
                W[12][2] = t2;
                t3 ^= t2;
                W[12][3] = t3;
                break;
            }
            case 8:
            {
                uint t0 = key.ToUInt32(0);
                W[0][0] = t0;
                uint t1 = key.ToUInt32(4);
                W[0][1] = t1;
                uint t2 = key.ToUInt32(8);
                W[0][2] = t2;
                uint t3 = key.ToUInt32(12);
                W[0][3] = t3;
                uint t4 = key.ToUInt32(16);
                W[1][0] = t4;
                uint t5 = key.ToUInt32(20);
                W[1][1] = t5;
                uint t6 = key.ToUInt32(24);
                W[1][2] = t6;
                uint t7 = key.ToUInt32(28);
                W[1][3] = t7;

                uint u, rcon = 1;

                for (int i = 2; i < 14; i += 2)
                {
                    u = SubWord(AesGaloisField.Shift(t7, 8)) ^ rcon;
                    rcon <<= 1;
                    t0 ^= u;
                    W[i][0] = t0;
                    t1 ^= t0;
                    W[i][1] = t1;
                    t2 ^= t1;
                    W[i][2] = t2;
                    t3 ^= t2;
                    W[i][3] = t3;
                    u = SubWord(t3);
                    t4 ^= u;
                    W[i + 1][0] = t4;
                    t5 ^= t4;
                    W[i + 1][1] = t5;
                    t6 ^= t5;
                    W[i + 1][2] = t6;
                    t7 ^= t6;
                    W[i + 1][3] = t7;
                }

                u = SubWord(AesGaloisField.Shift(t7, 8)) ^ rcon;
                t0 ^= u;
                W[14][0] = t0;
                t1 ^= t0;
                W[14][1] = t1;
                t2 ^= t1;
                W[14][2] = t2;
                t3 ^= t2;
                W[14][3] = t3;
                break;
            }
            default:
                throw new InvalidOperationException("Should never get here");
        }

        if (!encrypting)
        {
            for (int j = 1; j < _rounds; j++)
            {
                uint[] w = W[j];
                for (int i = 0; i < 4; i++)
                {
                    w[i] = AesGaloisField.InverseMixColumn(w[i]);
                }
            }
        }

        return W;
    }

    private int EncryptBlock(ReadOnlySpan<byte> input, Span<byte> output, uint[][] KW)
    {
        uint C0 = input.ToUInt32();
        uint C1 = input[4..].ToUInt32();
        uint C2 = input[8..].ToUInt32();
        uint C3 = input[12..].ToUInt32();

        uint[] kw = KW[0];
        uint t0 = C0 ^ kw[0];
        uint t1 = C1 ^ kw[1];
        uint t2 = C2 ^ kw[2];

        uint r0, r1, r2, r3 = C3 ^ kw[3];
        int r = 1;
        while (r < _rounds - 1)
        {
            kw = KW[r++];
            r0 = AesTableCipher.T0[t0 & 255] ^ AesGaloisField.Shift(AesTableCipher.T0[(t1 >> 8) & 255], 24) ^ AesGaloisField.Shift(AesTableCipher.T0[(t2 >> 16) & 255], 16) ^
                 AesGaloisField.Shift(AesTableCipher.T0[(r3 >> 24) & 255], 8) ^ kw[0];
            r1 = AesTableCipher.T0[t1 & 255] ^ AesGaloisField.Shift(AesTableCipher.T0[(t2 >> 8) & 255], 24) ^ AesGaloisField.Shift(AesTableCipher.T0[(r3 >> 16) & 255], 16) ^
                 AesGaloisField.Shift(AesTableCipher.T0[(t0 >> 24) & 255], 8) ^ kw[1];
            r2 = AesTableCipher.T0[t2 & 255] ^ AesGaloisField.Shift(AesTableCipher.T0[(r3 >> 8) & 255], 24) ^ AesGaloisField.Shift(AesTableCipher.T0[(t0 >> 16) & 255], 16) ^
                 AesGaloisField.Shift(AesTableCipher.T0[(t1 >> 24) & 255], 8) ^ kw[2];
            r3 = AesTableCipher.T0[r3 & 255] ^ AesGaloisField.Shift(AesTableCipher.T0[(t0 >> 8) & 255], 24) ^ AesGaloisField.Shift(AesTableCipher.T0[(t1 >> 16) & 255], 16) ^
                 AesGaloisField.Shift(AesTableCipher.T0[(t2 >> 24) & 255], 8) ^ kw[3];
            kw = KW[r++];
            t0 = AesTableCipher.T0[r0 & 255] ^ AesGaloisField.Shift(AesTableCipher.T0[(r1 >> 8) & 255], 24) ^ AesGaloisField.Shift(AesTableCipher.T0[(r2 >> 16) & 255], 16) ^
                 AesGaloisField.Shift(AesTableCipher.T0[(r3 >> 24) & 255], 8) ^ kw[0];
            t1 = AesTableCipher.T0[r1 & 255] ^ AesGaloisField.Shift(AesTableCipher.T0[(r2 >> 8) & 255], 24) ^ AesGaloisField.Shift(AesTableCipher.T0[(r3 >> 16) & 255], 16) ^
                 AesGaloisField.Shift(AesTableCipher.T0[(r0 >> 24) & 255], 8) ^ kw[1];
            t2 = AesTableCipher.T0[r2 & 255] ^ AesGaloisField.Shift(AesTableCipher.T0[(r3 >> 8) & 255], 24) ^ AesGaloisField.Shift(AesTableCipher.T0[(r0 >> 16) & 255], 16) ^
                 AesGaloisField.Shift(AesTableCipher.T0[(r1 >> 24) & 255], 8) ^ kw[2];
            r3 = AesTableCipher.T0[r3 & 255] ^ AesGaloisField.Shift(AesTableCipher.T0[(r0 >> 8) & 255], 24) ^ AesGaloisField.Shift(AesTableCipher.T0[(r1 >> 16) & 255], 16) ^
                 AesGaloisField.Shift(AesTableCipher.T0[(r2 >> 24) & 255], 8) ^ kw[3];
        }

        kw = KW[r++];
        r0 = AesTableCipher.T0[t0 & 255] ^ AesGaloisField.Shift(AesTableCipher.T0[(t1 >> 8) & 255], 24) ^ AesGaloisField.Shift(AesTableCipher.T0[(t2 >> 16) & 255], 16) ^
             AesGaloisField.Shift(AesTableCipher.T0[(r3 >> 24) & 255], 8) ^ kw[0];
        r1 = AesTableCipher.T0[t1 & 255] ^ AesGaloisField.Shift(AesTableCipher.T0[(t2 >> 8) & 255], 24) ^ AesGaloisField.Shift(AesTableCipher.T0[(r3 >> 16) & 255], 16) ^
             AesGaloisField.Shift(AesTableCipher.T0[(t0 >> 24) & 255], 8) ^ kw[1];
        r2 = AesTableCipher.T0[t2 & 255] ^ AesGaloisField.Shift(AesTableCipher.T0[(r3 >> 8) & 255], 24) ^ AesGaloisField.Shift(AesTableCipher.T0[(t0 >> 16) & 255], 16) ^
             AesGaloisField.Shift(AesTableCipher.T0[(t1 >> 24) & 255], 8) ^ kw[2];
        r3 = AesTableCipher.T0[r3 & 255] ^ AesGaloisField.Shift(AesTableCipher.T0[(t0 >> 8) & 255], 24) ^ AesGaloisField.Shift(AesTableCipher.T0[(t1 >> 16) & 255], 16) ^
             AesGaloisField.Shift(AesTableCipher.T0[(t2 >> 24) & 255], 8) ^ kw[3];

        // Final round
        kw = KW[r];
        C0 = (uint)AesTableCipher.S[r0 & 255] ^ (((uint)AesTableCipher.S[(r1 >> 8) & 255]) << 8) ^ (((uint)AesTableCipher.S[(r2 >> 16) & 255]) << 16) ^
             (((uint)AesTableCipher.S[(r3 >> 24) & 255]) << 24) ^ kw[0];
        C1 = (uint)AesTableCipher.S[r1 & 255] ^ (((uint)AesTableCipher.S[(r2 >> 8) & 255]) << 8) ^ (((uint)AesTableCipher.S[(r3 >> 16) & 255]) << 16) ^
             (((uint)AesTableCipher.S[(r0 >> 24) & 255]) << 24) ^ kw[1];
        C2 = (uint)AesTableCipher.S[r2 & 255] ^ (((uint)AesTableCipher.S[(r3 >> 8) & 255]) << 8) ^ (((uint)AesTableCipher.S[(r0 >> 16) & 255]) << 16) ^
             (((uint)AesTableCipher.S[(r1 >> 24) & 255]) << 24) ^ kw[2];
        C3 = (uint)AesTableCipher.S[r3 & 255] ^ (((uint)AesTableCipher.S[(r0 >> 8) & 255]) << 8) ^ (((uint)AesTableCipher.S[(r1 >> 16) & 255]) << 16) ^
             (((uint)AesTableCipher.S[(r2 >> 24) & 255]) << 24) ^ kw[3];

        C0.ToRawByte(output);
        C1.ToRawByte(output[4..]);
        C2.ToRawByte(output[8..]);
        C3.ToRawByte(output[12..]);

        return BlockSize;
    }

    private int DecryptBlock(ReadOnlySpan<byte> input, Span<byte> output, uint[][] KW)
    {
        uint C0 = input.ToUInt32();
        uint C1 = input[4..].ToUInt32();
        uint C2 = input[8..].ToUInt32();
        uint C3 = input[12..].ToUInt32();

        uint[] kw = KW[_rounds];
        uint t0 = C0 ^ kw[0];
        uint t1 = C1 ^ kw[1];
        uint t2 = C2 ^ kw[2];

        uint r0, r1, r2, r3 = C3 ^ kw[3];
        int r = _rounds - 1;
        while (r > 1)
        {
            kw = KW[r--];
            r0 = AesTableCipher.Tinv0[t0 & 255] ^ AesGaloisField.Shift(AesTableCipher.Tinv0[(r3 >> 8) & 255], 24) ^ AesGaloisField.Shift(AesTableCipher.Tinv0[(t2 >> 16) & 255], 16) ^
                 AesGaloisField.Shift(AesTableCipher.Tinv0[(t1 >> 24) & 255], 8) ^ kw[0];
            r1 = AesTableCipher.Tinv0[t1 & 255] ^ AesGaloisField.Shift(AesTableCipher.Tinv0[(t0 >> 8) & 255], 24) ^ AesGaloisField.Shift(AesTableCipher.Tinv0[(r3 >> 16) & 255], 16) ^
                 AesGaloisField.Shift(AesTableCipher.Tinv0[(t2 >> 24) & 255], 8) ^ kw[1];
            r2 = AesTableCipher.Tinv0[t2 & 255] ^ AesGaloisField.Shift(AesTableCipher.Tinv0[(t1 >> 8) & 255], 24) ^ AesGaloisField.Shift(AesTableCipher.Tinv0[(t0 >> 16) & 255], 16) ^
                 AesGaloisField.Shift(AesTableCipher.Tinv0[(r3 >> 24) & 255], 8) ^ kw[2];
            r3 = AesTableCipher.Tinv0[r3 & 255] ^ AesGaloisField.Shift(AesTableCipher.Tinv0[(t2 >> 8) & 255], 24) ^ AesGaloisField.Shift(AesTableCipher.Tinv0[(t1 >> 16) & 255], 16) ^
                 AesGaloisField.Shift(AesTableCipher.Tinv0[(t0 >> 24) & 255], 8) ^ kw[3];
            kw = KW[r--];
            t0 = AesTableCipher.Tinv0[r0 & 255] ^ AesGaloisField.Shift(AesTableCipher.Tinv0[(r3 >> 8) & 255], 24) ^ AesGaloisField.Shift(AesTableCipher.Tinv0[(r2 >> 16) & 255], 16) ^
                 AesGaloisField.Shift(AesTableCipher.Tinv0[(r1 >> 24) & 255], 8) ^ kw[0];
            t1 = AesTableCipher.Tinv0[r1 & 255] ^ AesGaloisField.Shift(AesTableCipher.Tinv0[(r0 >> 8) & 255], 24) ^ AesGaloisField.Shift(AesTableCipher.Tinv0[(r3 >> 16) & 255], 16) ^
                 AesGaloisField.Shift(AesTableCipher.Tinv0[(r2 >> 24) & 255], 8) ^ kw[1];
            t2 = AesTableCipher.Tinv0[r2 & 255] ^ AesGaloisField.Shift(AesTableCipher.Tinv0[(r1 >> 8) & 255], 24) ^ AesGaloisField.Shift(AesTableCipher.Tinv0[(r0 >> 16) & 255], 16) ^
                 AesGaloisField.Shift(AesTableCipher.Tinv0[(r3 >> 24) & 255], 8) ^ kw[2];
            r3 = AesTableCipher.Tinv0[r3 & 255] ^ AesGaloisField.Shift(AesTableCipher.Tinv0[(r2 >> 8) & 255], 24) ^ AesGaloisField.Shift(AesTableCipher.Tinv0[(r1 >> 16) & 255], 16) ^
                 AesGaloisField.Shift(AesTableCipher.Tinv0[(r0 >> 24) & 255], 8) ^ kw[3];
        }

        kw = KW[1];
        r0 = AesTableCipher.Tinv0[t0 & 255] ^ AesGaloisField.Shift(AesTableCipher.Tinv0[(r3 >> 8) & 255], 24) ^ AesGaloisField.Shift(AesTableCipher.Tinv0[(t2 >> 16) & 255], 16) ^
             AesGaloisField.Shift(AesTableCipher.Tinv0[(t1 >> 24) & 255], 8) ^ kw[0];
        r1 = AesTableCipher.Tinv0[t1 & 255] ^ AesGaloisField.Shift(AesTableCipher.Tinv0[(t0 >> 8) & 255], 24) ^ AesGaloisField.Shift(AesTableCipher.Tinv0[(r3 >> 16) & 255], 16) ^
             AesGaloisField.Shift(AesTableCipher.Tinv0[(t2 >> 24) & 255], 8) ^ kw[1];
        r2 = AesTableCipher.Tinv0[t2 & 255] ^ AesGaloisField.Shift(AesTableCipher.Tinv0[(t1 >> 8) & 255], 24) ^ AesGaloisField.Shift(AesTableCipher.Tinv0[(t0 >> 16) & 255], 16) ^
             AesGaloisField.Shift(AesTableCipher.Tinv0[(r3 >> 24) & 255], 8) ^ kw[2];
        r3 = AesTableCipher.Tinv0[r3 & 255] ^ AesGaloisField.Shift(AesTableCipher.Tinv0[(t2 >> 8) & 255], 24) ^ AesGaloisField.Shift(AesTableCipher.Tinv0[(t1 >> 16) & 255], 16) ^
             AesGaloisField.Shift(AesTableCipher.Tinv0[(t0 >> 24) & 255], 8) ^ kw[3];

        // Final round
        kw = KW[0];
        C0 = (uint)AesTableCipher.Si[r0 & 255] ^ (((uint)AesTableCipher.Si[(r3 >> 8) & 255]) << 8) ^ (((uint)AesTableCipher.Si[(r2 >> 16) & 255]) << 16) ^
             (((uint)AesTableCipher.Si[(r1 >> 24) & 255]) << 24) ^ kw[0];
        C1 = (uint)AesTableCipher.Si[r1 & 255] ^ (((uint)AesTableCipher.Si[(r0 >> 8) & 255]) << 8) ^ (((uint)AesTableCipher.Si[(r3 >> 16) & 255]) << 16) ^
             (((uint)AesTableCipher.Si[(r2 >> 24) & 255]) << 24) ^ kw[1];
        C2 = (uint)AesTableCipher.Si[r2 & 255] ^ (((uint)AesTableCipher.Si[(r1 >> 8) & 255]) << 8) ^ (((uint)AesTableCipher.Si[(r0 >> 16) & 255]) << 16) ^
             (((uint)AesTableCipher.Si[(r3 >> 24) & 255]) << 24) ^ kw[2];
        C3 = (uint)AesTableCipher.Si[r3 & 255] ^ (((uint)AesTableCipher.Si[(r2 >> 8) & 255]) << 8) ^ (((uint)AesTableCipher.Si[(r1 >> 16) & 255]) << 16) ^
             (((uint)AesTableCipher.Si[(r0 >> 24) & 255]) << 24) ^ kw[3];

        C0.ToRawByte(output);
        C1.ToRawByte(output[4..]);
        C2.ToRawByte(output[8..]);
        C3.ToRawByte(output[12..]);

        return BlockSize;
    }

    #endregion
    
    #endregion
    
}