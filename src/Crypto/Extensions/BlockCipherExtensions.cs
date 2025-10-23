using Crypto.Domain.Exceptions;
using Crypto.Domain.Interfaces;
using Crypto.Domain.Parameters;

namespace Crypto.Extensions
{
    public static class BlockCipherExtensions
    {

        #region Encrypt
        
        public static byte[] Encrypt(
            this ICipherOperator cipherOperator,
            byte[] key,
            byte[] plaintext)
        {
            return cipherOperator.Encrypt(new SymmetricKey(key), plaintext);
        }
        
        public static byte[] Encrypt(
            this ICipherOperator cipherOperator,
            ICryptoParams param,
            byte[] plaintext)
        {
            cipherOperator.Setup(true, param);
            return cipherOperator.ProcessAll(plaintext);
        }
        
        public static byte[] Encrypt(
            this ICipherOperator cipherOperator,
            byte[] key,
            byte[] iv,
            byte[] plaintext)
        {
           return cipherOperator.Encrypt(
               new SymmetricKey(key),
               iv, 
               plaintext);
        }
        
        public static byte[] Encrypt(
            this ICipherOperator cipherOperator,
            ICryptoParams keyParam,
            byte[] iv,
            byte[] plaintext)
        {
            cipherOperator.Setup(true,
                new IVWithParams(keyParam, iv));
            
            return cipherOperator.ProcessAll(plaintext);
        }

        
        #endregion
        
        #region Decrypt
        
               
        public static byte[] Decrypt(
            this ICipherOperator cipherOperator,
            byte[] key,
            byte[] ciphertext)
        {
            return cipherOperator.Decrypt(new SymmetricKey(key), ciphertext);
        }

        public static byte[] Decrypt(
            this ICipherOperator cipherOperator,
            ICryptoParams param,
            byte[] ciphertext)
        {
            cipherOperator.Setup(false, param);
            return cipherOperator.ProcessAll(ciphertext);
        }

        public static byte[] Decrypt(
            this ICipherOperator cipherOperator,
            byte[] key,
            byte[] iv,
            byte[] ciphertext)
        {
            return cipherOperator.Decrypt(new SymmetricKey(key), iv, ciphertext);
        }

        public static byte[] Decrypt(
            this ICipherOperator cipherOperator,
            ICryptoParams keyParam,
            byte[] iv,
            byte[] ciphertext)
        {
            cipherOperator.Setup(false, new IVWithParams(keyParam, iv));
            return cipherOperator.ProcessAll(ciphertext);
        }
        
        #endregion
        
        #region Processing Byte
        
        public static int ProcessByte(
            this ICipherOperator cipherOperator,
            byte input,
            byte[] output,
            int outOff)
        {
            byte[] outBytes = cipherOperator.ProcessByte(input);
            if (outBytes == null)
                return 0;
            if (outOff + outBytes.Length > output.Length)
                throw new ParameterLengthException("output buffer too short");
            outBytes.CopyTo(output, outOff);
            return outBytes.Length;
        }
        
        #endregion
        
        #region Processing blocks
        
        public static byte[] ProcessBlocks(
            this ICipherOperator cipherOperator,
            byte[] input)
        {
            return cipherOperator.ProcessBlocks(input, 0, input.Length);
        }
        
        public static int ProcessBlocks(
            this ICipherOperator cipherOperator,
            byte[] input,
            byte[] output,
            int outOff)
        {
            return cipherOperator.ProcessBlocks(input, 0, input.Length, output, outOff);
        }
        
        public static int ProcessBlocks(
            this ICipherOperator cipherOperator,
            byte[] input,
            int inOff,
            int length,
            byte[] output,
            int outOff)
        {
            byte[] outBytes = cipherOperator.ProcessBlocks(input, inOff, length);
            
            if (outBytes == null)
            {
                return 0;
            }
            
            if (outOff + outBytes.Length > output.Length)
                throw new ParameterLengthException("output buffer too short");
            outBytes.CopyTo(output, outOff);
            return outBytes.Length;
        }

        
        public static byte[] Encrypt(
            this IBlockCipher cipherEngine,
            ICryptoParams cryptoParams,
            byte[] input)
        {
            return cipherEngine.ProcessBlock(true, cryptoParams, input);
        }
        
        public static byte[] Decrypt(
            this IBlockCipher cipherEngine,
            ICryptoParams cryptoParams,
            byte[] input)
        {
            return cipherEngine.ProcessBlock(false, cryptoParams, input);
        }

        public static byte[] ProcessBlock(
            this IBlockCipher cipherEngine,
            bool encrypting,
            ICryptoParams cryptoParams,
            byte[] input)
        {
            byte[] result = new  byte[input.Length];
            
            cipherEngine.Setup(encrypting, cryptoParams);
            
            cipherEngine.ProcessBlock(input, 0, result, 0);

            return result;
        }
        
        #endregion
        
        #region Processing block final
        
        public static int ProcessBlockFinal(
            this ICipherOperator cipherOperator,
            byte[] input,
            byte[] output,
            int outOff)
        {
            return cipherOperator.ProcessBlockFinal(input, 0, input.Length, output, outOff);
        }
        
        public static int ProcessBlockFinal(
            this ICipherOperator cipherOperator,
            byte[] input,
            int inOff,
            int length,
            byte[] output,
            int outOff)
        {
            int len = cipherOperator.ProcessBlocks(input, inOff, length, output, outOff);
            len += cipherOperator.ProcessBlockFinal(output, outOff + len);
            return len;
        }
        
        
        #endregion
        
        #region Processing all blocks
        
        public static byte[] ProcessAll(
            this ICipherOperator cipherOperator,
            byte[] input)
        {
            return cipherOperator.ProcessAll(input, 0, input.Length);
        }
        
        #endregion
        
        #region Setup
        public static void Setup(
            this ICipherOperator cipherOperator,
            bool encrypting,
            byte[] key)
        {
            cipherOperator.Setup(encrypting, new SymmetricKey(key));
        }
        
        #endregion
        
    
    }
}