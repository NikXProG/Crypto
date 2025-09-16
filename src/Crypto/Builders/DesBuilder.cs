using Crypto.Ciphers;
using Crypto.Core;
using Crypto.Core.Interfaces;
using Crypto.Symmetrical.Algorithms;

namespace Crypto.Symmetrical.Builders
{
    
    public class DesBuilder : IDesBuilder
    {
        
        private CipherMode _mode;
        private PaddingMode _padding;
        private byte[]? _key;
        private byte[]? _iv;
        private bool _generateKey;
        private bool _generateIV;

        public IDesBuilder WithCipherMode(CipherMode cipherMode)
        {
            _mode = cipherMode;
            return this;
        }

        public IDesBuilder WithPadding(PaddingMode padding)
        {
            _padding = padding;
            return this;
        }
        
        public IDesBuilder WithKey(byte[] key)
        {
            _key = key;
            _generateKey = false;
            return this;
        }

        public IDesBuilder WithIV(byte[] iv)
        {
            _iv = iv;
            _generateIV = false;
            return this;
        }

        public IDesBuilder UseGenerateIV()
        {
            _generateIV = true;
            return this;
        }

        public IDesBuilder UseGenerateKey()
        {
            _generateKey = true;
            return this;
        }
        
        public ISymmetrical Build()
        {
            ISymmetrical des = new DesCipher();

            // HandleKey(des);
            // HandleIV(des);
            
            des.Mode = _mode;
            des.Padding = _padding;

            return des;
        }
        
        // private void HandleKey(ISymmetrical algorithm)
        // {
        //     if (_key != null)
        //     {
        //         algorithm.Key = _key;
        //         return;
        //     }
        //
        //     if (!_generateKey) 
        //         throw new InvalidOperationException("Key must be provided or generated");
        //    
        //     algorithm.GenerateKey();
        //
        // }
        //
        // private void HandleIV(ISymmetrical algorithm)
        // {
        //     if (_iv != null)
        //     {
        //         algorithm.IV = _iv;
        //         return;
        //     }
        //
        //     if (_generateIV)
        //     {
        //         algorithm.GenerateIV();
        //         return;
        //     }
        //     
        //     if (_mode != CipherMode.ECB)
        //         throw new InvalidOperationException("IV must be provided or generated for selected mode");
        // }

        
    }
}