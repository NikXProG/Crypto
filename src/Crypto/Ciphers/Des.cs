using System.Buffers.Binary;
using System.Security.Cryptography;
using Crypto.Cipher.Symmetrical;
using Crypto.Core;
using Crypto.Core.Exceptions;
using Crypto.Core.Extensions;
using Crypto.Core.Interfaces;
using Crypto.Symmetrical;
using Crypto.Symmetrical.Algorithms;
using CipherMode = Crypto.Core.CipherMode;
using PaddingMode = Crypto.Core.PaddingMode;

namespace Crypto.Ciphers
{
    
    public sealed class DesCipher : ISymmetrical
    {
        
        #region Fields

        #region Symmetrical Fields

        private CipherMode _mode;
        private PaddingMode _padding;
        private byte[]? _key;
        private byte[]? _iv;
        private int _blockSize;
        private int _keySize;
        private int _feedbackSize;
        private ValidRangeSize[]? _blockValidRanges;
        private ValidRangeSize[]? _keyValidRanges;

        #endregion
        
        #region Parameter Ranges
        
        private static readonly ValidRangeSize[] s_validBlockRanges  =
        {
            new ValidRangeSize(minSize: 64, maxSize: 64, stepSize: 0)
        };

        private static readonly ValidRangeSize[] s_ValidKeyRanges  =
        {
            new ValidRangeSize(minSize: 64, maxSize: 64, stepSize: 0)
        };
        
        #endregion
        
        internal const int BlockSegmentSize = 8;
        
        #endregion
        
        #region Constructors
        
        public DesCipher()
        {
            _mode = CipherMode.CTR;
            _padding = PaddingMode.PKCS7;
            _blockValidRanges = s_validBlockRanges;
            _keyValidRanges = s_ValidKeyRanges;
            _blockSize = 64;
            _keySize = 64;
            _feedbackSize = BlockSegmentSize;
        }
        
        #endregion
        
        #region Properties 
        
        public string AlgorithmName => "DES";
    
        /// <summary>
        /// Initialization Vector (IV) for encryption modes.
        /// Serves as the initial byte sequence
        /// to randomize the encryption process
        /// and prevent repeating patterns in encrypted data.
        /// </summary>
        /// <remarks>
        /// With the same keys and different initialization vectors,
        /// the encryption result will be different. 
        /// Requires uniqueness for each encryption session with the same key.
        /// </remarks>
        public byte[] IV
        {
            get
            {
                if (_iv == null)
                {
                    GenerateIV();
                }
                
                return _iv.CloneByteArray()!;
            }
    
            set
            {
                ArgumentNullException.ThrowIfNull(value);
                if (value.Length != this.BlockSize / 8)
                    throw new CryptoException("Invalid size for IV");
                _iv = value.CloneByteArray();
            }
        }

        /// <summary>
        /// property specifies the key for encryption
        /// </summary>
        public byte[] Key
        {
            get
            {
                if (_key == null)
                {
                    GenerateKey();
                }
                
                return _key.CloneByteArray()!;
            }
            set
            {
                ArgumentNullException.ThrowIfNull(value);
        
                long bitLength = value.Length * 8L;
                if (bitLength > int.MaxValue || !ValidKeySize((int)bitLength))
                    throw new CryptoException("Invalid key size");
        
                // must convert bytes to bits
                this.KeySize = (int)bitLength;
                _key = value.CloneByteArray();
            }
        }
        
        /// <summary>
        /// defines the number of bits of the encryption key
        /// </summary>
        public int KeySize
        {
            get => _keySize;
            set
            {
                if (!ValidKeySize(value))
                {
                    throw new CryptoException("Invalid key size");
                }
                
                _keySize = value;
                _key = null;
            }
        }

        /// <summary>
        /// defines the block text encryption mode
        /// </summary>
        public CipherMode Mode
        {
            get => _mode;
            set
            {
                if ((value < CipherMode.CBC) || (value > CipherMode.ECB))
                    throw new CryptoException("Invalid range for padding mode"); 
                _mode = value;
            }
        }

        /// <summary>
        /// determines the number of bit blocks into which the message is divided
        /// </summary>
        public int BlockSize
        {
            get => _blockSize;
            set
            {
                bool validatedByZeroSkipSizeKeySizes;
                if (!value.IsValidSize(this.KeyValidRanges, out validatedByZeroSkipSizeKeySizes))
                    throw new CryptoException("Invalid key size");

                if (_blockSize == value && !validatedByZeroSkipSizeKeySizes) // The !validatedByZeroSkipSizeKeySizes check preserves a very obscure back-compat behavior.
                    return;

                _blockSize = value;
                _iv = null;
            }
        }

        public  int FeedbackSize
        {
            get;
            set;
        }

        /// <summary>
        /// determines how to align the last block of the bit sequence
        /// </summary>
        public PaddingMode Padding
        {
            get => _padding;
            set
            {
                if ((value < PaddingMode.None) || (value > PaddingMode.ISO10126))
                    throw new CryptoException("Invalid range for padding mode"); 
                _padding = value;
            }
        }
    
        public ValidRangeSize[] KeyValidRanges =>
            (ValidRangeSize[])_keyValidRanges!.Clone();
        
        public ValidRangeSize[] BlockValidRanges =>
            (ValidRangeSize[])_blockValidRanges!.Clone();
        
        #endregion
        
        #region Methods
        
        #region Public Methods

        public IEncryptor CreateEncryptor()
        {
            IBlockCipher engine = new DesEngine(
                Mode,
                Key,
                BlockSize,
                IV,
                FeedbackSize,
                BlockSize,
                encrypting: true);
            
            return new PaddedBlockEncryptor(new PaddingZeros(), engine);
        }
    
        public IDecryptor CreateDecryptor()
        {
            
            IBlockCipher engine = new DesEngine(
                Mode,
                Key,
                BlockSize,
                IV,
                FeedbackSize,
                BlockSize,
                encrypting: false);
            
            return new PaddedBlockDecryptor(Padding, engine);
        }
        
        public byte[] Decrypt(byte[] ciphertext)
        {
            throw new NotImplementedException();
        }

        public byte[] Encrypt(byte[] plaintext)
        {
            
            using (var ms = new MemoryStream())
            {
                using (var stream = new CryptoWriteStream(ms, CreateEncryptor()))
                {
                    
                    stream.FlushFinal();
                    
                    return ms.ToArray();
                }
            
            }
            
        }

        public static byte[] Encrypt(byte[] plaintext, byte[] key, byte[] iv)
        {
            var algorithm = CryptoFactory.CreateDes(iv, key);

            return algorithm.Encrypt(plaintext);
        }
        
        public static bool IsValidKey(byte[] key)
        {
            
            if (key == null || key.Length != 8)
                return false;
        
            return !DesWeakKeys.AllWeakKeys.Contains(GetNormalizedKey(key));
            
        }
        
        public void GenerateIV()
        {
            _iv = RandomNumberGenerator.GetBytes(BlockSize/BlockSegmentSize);
        }

        public void GenerateKey()
        {
            byte[] key = new byte[KeySize/BlockSegmentSize];
            RandomNumberGenerator.Fill(key);
            while (!IsValidKey(key))
            {
                RandomNumberGenerator.Fill(key);
            }
            _key = key;
        }
        
        #endregion
        
        #region Private Methods
        
        public bool ValidKeySize(int bitLength)
        {
            ValidRangeSize[] ranges = this.KeyValidRanges;
            if (ranges == null)
                return false;
            return bitLength.IsValidSize(ranges);
        }
        
        private static ulong GetNormalizedKey(byte[] key) =>
            BinaryPrimitives.ReadUInt64BigEndian(key.EnsureOddParity());
        
        #endregion
        
        #endregion
        
        
    }
    //
    // public abstract class DesCipher : SymmetricalAlgorithm, IFeistelNetwork
    // {
    //     
    //     #region Fields
    //     
    //     private FeistelNetSize _feistelNetSize;
    //     
    //     #endregion
    //     
    //     #region Constructors
    //     
    //     protected DesCipher()
    //     {
    //         DataBlockValidRangeSize = [
    //             new ValidRangeSize(64, 64, 0),
    //         ];
    //
    //         EncryptKeyValidRangeSize = [
    //             new ValidRangeSize(64, 64, 0),
    //         ];
    //         
    //         FeistelNetSize = FeistelNetSize.Medium;
    //         EncryptKeySize = 64;
    //         DataBlockSize = 64;
    //         
    //     }
    //     
    //     #endregion
    //
    //     #region Properties
    //
    //     #region Public properties
    //     
    //     /// <summary>
    //     /// determines how much our block will be divided
    //     /// </summary>
    //     public virtual FeistelNetSize FeistelSize
    //     {
    //         get => FeistelNetSize;
    //         set => FeistelNetSize = value;
    //     }
    //     
    //     public override byte[] Key
    //     {
    //         get
    //         {
    //             byte[] key = base.Key;
    //             while (!IsValidKey(key))
    //             {
    //                 GenerateKey();
    //                 key = base.Key;
    //             }
    //             return key;
    //         }
    //         set
    //         {
    //             ArgumentNullException.ThrowIfNull(value);
    //
    //             if (value.Length != 8)
    //             {
    //                 throw new CryptoException("Invalid key length", "DES");
    //             }
    //
    //             if (!IsValidKey(value))
    //             {
    //                 throw new CryptoException("Weak or semi-weak key detected", "DES");
    //             }
    //             
    //             base.Key = value;
    //         }
    //     }
    //     
    //     #endregion
    //     
    //     #region Protected properties
    //     
    //     protected FeistelNetSize FeistelNetSize
    //     {
    //         get => _feistelNetSize; 
    //         set => _feistelNetSize = value;
    //     }
    //     
    //     #endregion
    //     
    //     #endregion
    //     
    //     #region Methods 
    //     
    //     #region Public methods
    //     
    //     public static bool IsValidKey(byte[] key)
    //     {
    //         
    //         if (key == null || key.Length != 8)
    //             return false;
    //
    //         return !DesWeakKeys.AllWeakKeys.Contains(GetNormalizedKey(key));
    //         
    //     }
    //     
    //     #endregion
    //     
    //     #region Private methods
    //     
    //     private static ulong GetNormalizedKey(byte[] key) =>
    //         BinaryPrimitives.ReadUInt64BigEndian(key.EnsureOddParity());
    //     
    //     #endregion
    //     
    //     #endregion
    //     
    //     
    // }
    
}
