using Crypto.Domain.Interfaces;
using Crypto.Domain.Parameters;
using Crypto.Helpers;
using Crypto.Utils;

namespace Crypto.Engines;

public class DealEngine : IBlockCipher
{
    
    #region Fields

    private readonly IDes _desEngineCore;
    private int[][] _roundKeys;
    private int _rounds;
    private bool _encrypting;
    
    private const int BlockSize = 16;
    
    #endregion
    
    #region Constructors
    
    public DealEngine() : 
        this(new DesEngineCore())
    {
    }

    public DealEngine(IDes desEngineCore)
    {
        _desEngineCore = desEngineCore ?? throw new ArgumentNullException(nameof(desEngineCore));
    }
    
    #endregion
    
    #region Properties

    public int BlockSizeInBytes => BlockSize;

    #endregion
    
    #region Methods

    public void Setup(bool encrypting, ICryptoParams cryptoParams)
    {
        if (!(cryptoParams is SymmetricKey symmetricKey))
            throw new ArgumentException($"{nameof(cryptoParams)} must be of type {nameof(SymmetricKey)} for deal engine.");

        byte[] key = symmetricKey.GetKey();
        
        _rounds = key.Length switch
        {
            16 => 6, // 128 bits
            24 => 6, // 192 bits
            32 => 8, // 256 bits
            _ => throw new ArgumentException("DEAL key must be 128, 192 or 256 bits")
        };

        _encrypting = encrypting;
        
        _roundKeys = Enumerable.Range(0, _rounds)
            .Select(i => _desEngineCore.TransformKey(true, DeriveRoundKey(key, i)))
            .ToArray();
     
    }

    public int ProcessBlock(byte[] inBuf, int inOff, byte[] outBuf, int outOff)
    {
        return ProcessBlock(
            inBuf.AsSpan(inOff), 
            outBuf.AsSpan(outOff));
    }
    
    public int ProcessBlock(ReadOnlySpan<byte> input, Span<byte> output)
    {
        if (_roundKeys == null)
        {
            throw new InvalidOperationException("DEAL engine - key not initialized");
        }

        Guard.ValidLength(input, BlockSize, "input buffer too short");
        Guard.ValidLength(output, BlockSize, "output buffer too short");

        ulong left = input.ToUInt64();     
        ulong right = input[8..].ToUInt64(); 
        
        if (_encrypting)
        {
            EncryptRoundsKey(_roundKeys, ref left, ref right);
        }
        else
        {
            DecryptRoundsKey(_roundKeys, ref left, ref right);
        }
        
        left.ToRawByte(output);
        right.ToRawByte(output[8..]);

        return BlockSize;
    }
    
    private void EncryptRoundsKey(int[][] roundKeys, ref ulong left, ref ulong right)
    {
        for (int round = 0; round < roundKeys.Length; round++)
        {
      
            ulong fResult = ApplyDes(right, roundKeys[round]);
            (left, right) = (right, left ^ fResult);
        }
    }
   
        
    private void DecryptRoundsKey(int[][] roundKeys, ref ulong left, ref ulong right)
    {
        for (int round = roundKeys.Length - 1; round >= 0; round--)
        {
            ulong fResult = ApplyDes(left, roundKeys[round]);
            (left, right) = (right ^ fResult, left);
        }
    }
    
    private ulong ApplyDes(ulong block, int[] roundKey)
    {
        uint hi = (uint)(block >> 32);
        uint lo = (uint)block;
        _desEngineCore.DesFunc(roundKey, ref hi, ref lo);
        return ((ulong)hi << 32) | lo;
    }

    private static byte[] DeriveRoundKey(byte[] masterKey, int round)
    {
        var key = new byte[8];
        for (int i = 0; i < 8; i++)
        {
            int idx = (round * 8 + i) % masterKey.Length;
            key[i] = (byte)(masterKey[idx] ^ ((round * 7 + i * 3) & 0xFF));
        }
        return key;
    }

    #endregion
}
