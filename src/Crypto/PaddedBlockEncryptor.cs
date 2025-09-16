using Crypto.Core;
using Crypto.Core.Interfaces;

namespace Crypto.Symmetrical
{
    
    public class PaddedBlockEncryptor : IEncryptor
    {
        
        #region Fields
        
        private readonly IBlockCipherPadding _padding;
        private readonly IBlockCipher _engine;
        
        #endregion

        #region Constructors
        
        public PaddedBlockEncryptor(IBlockCipherPadding padding,IBlockCipher engine)
        {
            _padding = padding ?? throw new ArgumentNullException(nameof(padding));
            _engine = engine ?? throw new ArgumentNullException(nameof(engine));
        }
        
        #endregion
        
        #region Properties
        
        public bool CanReuseTransform { get; }

        public int InputBlockSize { get; }

        public bool CanTransformMultipleBlocks { get; }

        public int OutputBlockSize { get; }
        
        protected IBlockCipherPadding PaddingCipher => _padding;
        protected IBlockCipher BlockCipher => _engine;
        
        #endregion

        #region Methods
        
        public int EncryptBlock(
            byte[] inputBuffer, 
            int inputOffset,
            int inputCount, 
            byte[] outputBuffer,
            int outputOffset)
        {
            return _engine.ProcessBlock(inputBuffer, outputBuffer);
        }

        public byte[] EncryptFinalBlock(
            byte[] inputBuffer, 
            int inputOffset,
            int inputCount)
        {
            // int padWritten = SymmetricPadding.PadBlock(inputBuffer, outputBuffer, PaddingSizeBytes, PaddingMode);
            // int transformWritten = .TransformFinal(outputBuffer.Slice(0, padWritten), outputBuffer);
            //
            //
           // return _engine.ProcessBlockFinal(inputBuffer, inputOffset);

           
           var bytes = new byte[2];
           
           return bytes;
        }
    
        #endregion
        
    }
}
