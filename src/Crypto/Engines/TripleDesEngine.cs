using Crypto.Domain.Interfaces;
using Crypto.Domain.Parameters;
using Crypto.Helpers;
using Crypto.Utils;

namespace Crypto.Engines;

public class TripleDesEngine : IBlockCipher
{
    
    #region Fields

    private readonly IDes _desEngineCore;
    private int[] _key1, _key2, _key3;
    private bool _encrypting;

    private const int BlockSize = 8;
    
    #endregion
    
    #region Constructors

    public TripleDesEngine() :
        this(new DesEngineCore())
    {
        
    }
    
    public TripleDesEngine(IDes desEngineCore)
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
            throw new ArgumentException($"{nameof(cryptoParams)} must be of type {nameof(SymmetricKey)} for Triple DES.");

        byte[] key = symmetricKey.GetKey();
        
        if (key.Length != 24 && key.Length != 16)
            throw new ArgumentException("key size must be 16 or 24 bytes.");
        
        this._encrypting = encrypting;

        byte[] key1 = new byte[8];
        Array.Copy(key, 0, key1, 0, key1.Length);
        _key1 = _desEngineCore.TransformKey(_encrypting, key1);

        byte[] key2 = new byte[8];
        Array.Copy(key, 8, key2, 0, key2.Length);
        _key2 = _desEngineCore.TransformKey(!_encrypting, key2);

        if (key.Length != 24)
        {
            _key3 = _key1;
            return;
        }
   
        byte[] key3 = new byte[8];
        Array.Copy(key, 16, key3, 0, key3.Length);
        _key3 = _desEngineCore.TransformKey(_encrypting, key3);

        
    }

    public int ProcessBlock(byte[] inBuf, int inOff, byte[] outBuf, int outOff)
    {
        return ProcessBlock(
            inBuf.AsSpan(inOff), 
            outBuf.AsSpan(outOff));
    }
    
    public int ProcessBlock(ReadOnlySpan<byte> input, Span<byte> output)
    {
        if (_key1 == null)
            throw new InvalidOperationException("Triple des engine not initialised");
        
        Guard.ValidLength(input, BlockSize, "input buffer too short");
        Guard.ValidLength(output, BlockSize, "output buffer too short");

        uint hi32 = input.ToUInt32();
        uint lo32 = input[4..].ToUInt32();

        if (_encrypting)
        {
            _desEngineCore.DesFunc(_key1, ref hi32, ref lo32);
            _desEngineCore.DesFunc(_key2, ref hi32, ref lo32);
            _desEngineCore.DesFunc(_key3, ref hi32, ref lo32);
        }
        else
        {
            _desEngineCore.DesFunc(_key3, ref hi32, ref lo32);
            _desEngineCore.DesFunc(_key2, ref hi32, ref lo32);
            _desEngineCore.DesFunc(_key1, ref hi32, ref lo32);
        }
        
        hi32.ToRawByte(output);
        lo32.ToRawByte(output[4..]);

        return BlockSize;
    }
    
    #endregion
    
}