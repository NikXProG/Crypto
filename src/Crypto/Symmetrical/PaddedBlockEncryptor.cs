using Crypto.Core;
using Crypto.Core.Interfaces;
using Crypto.Engine.Core.Interfaces;

namespace Crypto.Symmetrical
{
    
    public class PaddedBlockEncryptor : IEncryptor
    {
        private PaddingMode _paddingMode;
        private ISymmetricalEngine _engine;

        public PaddedBlockEncryptor(PaddingMode paddingMode, ISymmetricalEngine engine)
        {
            _paddingMode = paddingMode;
            _engine = engine;
        }
    
        public bool CanReuseTransform { get; }

        public int InputBlockSize { get; }

        public bool CanTransformMultipleBlocks { get; }

        public int OutputBlockSize { get; }
        
        
        protected PaddingMode PaddingMode => _paddingMode;
        protected ISymmetricalEngine BasicSymmetricEngine => _engine;
        

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
    
    
    }
}
