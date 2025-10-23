using System.Buffers.Binary;
using Crypto.Domain.Interfaces;
using Crypto.Domain.Parameters;
using Crypto.Helpers;
using Crypto.Parameters;
using Crypto.Utils;

namespace Crypto.Engines
{
    public class DesEngine : IBlockCipher
    {

        #region Fields

        private readonly IDes _desEngineCore;
        
        private int[] _key;
        
        internal const int BlockSize = 8;

        #endregion
        
        #region Constructors

        public DesEngine() :
            this(new DesEngineCore())
        {
            
        }
        
        public DesEngine(IDes desEngineCore)
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
            if (cryptoParams is not SymmetricKey key)
            {
                throw new ArgumentException("invalid parameter passed to DES init");
            }

            _key = _desEngineCore.TransformKey(encrypting, key.GetKey());
        }

        public int ProcessBlock(byte[] inBuf, int inOff, byte[] outBuf, int outOff)
        {
            return ProcessBlock(
                inBuf.AsSpan(inOff), 
                outBuf.AsSpan(outOff));
        }
        

        public int ProcessBlock(ReadOnlySpan<byte> input, Span<byte> output)
        {
            if (_key == null)
            {
                throw new InvalidOperationException("DES engine - key not initialized");
            }
          
            Guard.ValidLength(input, BlockSize, "input buffer too short");
            Guard.ValidLength(output, BlockSize, "output buffer too short");
            
            uint hi32 = input.ToUInt32();
            uint lo32 = input[4..].ToUInt32();

            _desEngineCore.DesFunc(_key, ref hi32, ref lo32);
            
            hi32.ToRawByte(output);
            lo32.ToRawByte(output[4..]);
            
            return BlockSize;
        }
        
        #endregion
        
    }
}
