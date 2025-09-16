using Crypto.Core;
using Crypto.Core.Exceptions;
using Crypto.Core.Extensions;
using Crypto.Core.Interfaces;
using CipherMode = System.Security.Cryptography.CipherMode;
using PaddingMode = System.Security.Cryptography.PaddingMode;

namespace Crypto.Symmetrical.Algorithms;
//
// public abstract class SymmetricalBase : ISymmetricalGenerator
// {
//     
//     #region Fields
//
//     private CipherMode _mode;
//     private PaddingMode _padding;
//     private byte[]? _key;
//     private byte[]? _iv;
//     private int _blockSize;
//     private int _keySize;
//     private int _feedbackSize;
//     private ValidRangeSize[]? _blockValidRangeSizes;
//     private ValidRangeSize[]? _keyValidRangeSizes;
//             
//     #endregion
//     
//     #region Properties
//     
//     #region Public Properties
//     
//     /// <summary>
//     /// Initialization Vector (IV) for encryption modes.
//     /// Serves as the initial byte sequence
//     /// to randomize the encryption process
//     /// and prevent repeating patterns in encrypted data.
//     /// </summary>
//     /// <remarks>
//     /// With the same keys and different initialization vectors,
//     /// the encryption result will be different. 
//     /// Requires uniqueness for each encryption session with the same key.
//     /// </remarks>
//     public virtual byte[] IV
//     {
//         get
//         {
//             if (IVValue == null)
//                 GenerateIV();
//             return IVValue.CloneByteArray()!;
//         }
//     
//         set
//         {
//             ArgumentNullException.ThrowIfNull(value);
//             if (value.Length != this.BlockSize / 8)
//                 throw new CryptoException("Invalid size for IV");
//             IVValue = value.CloneByteArray();
//         }
//     }
//
//     /// <summary>
//     /// property specifies the key for encryption
//     /// </summary>
//     public virtual byte[] Key
//     {
//         get => KeyValue;
//         set => KeyValue = value;
//     }
//         
//     /// <summary>
//     /// defines the number of bits of the encryption key
//     /// </summary>
//     public virtual int KeySize
//     {
//         get;
//         set;
//     }
//
//     /// <summary>
//     /// defines the block text encryption mode
//     /// </summary>
//     public virtual CipherMode Mode
//     {
//         get;
//         set;
//     }
//
//     /// <summary>
//     /// determines the number of bit blocks into which the message is divided
//     /// </summary>
//     public virtual int BlockSize
//     {
//         get; 
//         set;
//     }
//
//     public  int FeedbackSize
//     {
//         get;
//         set;
//     }
//
//     /// <summary>
//     /// determines how to align the last block of the bit sequence
//     /// </summary>
//     public  PaddingMode Padding
//     {
//         get;
//         set;
//     }
//     
//     #endregion
//     
//     #region Protected Properties
//     
//     protected CipherMode ModeValue
//     {
//         get => _mode;
//         set => _mode = value;
//     }
//
//     protected PaddingMode PaddingValue
//     {
//         get => _padding;
//         set => _padding = value;
//     }
//
//     protected byte[]? KeyValue
//     {
//         get => _key;
//         set => _key = value;
//     }
//
//     protected byte[]? IVValue
//     {
//         get => _iv;
//         set => _iv = value;
//     }
//
//     protected int BlockSizeValue
//     {
//         get => _blockSize;
//         set => _blockSize = value;
//     }
//
//     protected int FeedbackSizeValue
//     {
//         get => _feedbackSize;
//         set => _feedbackSize = value;
//     }
//
//     protected int KeySizeValue
//     {
//         get => _keySize;
//         set => _keySize = value;
//     }
//         
//     /// <summary>
//     /// validatable range of sizes (max, min, step size) of the data block
//     /// </summary>
//     protected ValidRangeSize[]? BlockValidRangeSizesValue
//     {
//         get => _blockValidRangeSizes;
//         set => _blockValidRangeSizes = value;
//     }
//         
//     /// <summary>
//     /// validatable range of sizes (max, min, step size) of the key 
//     /// </summary>
//     protected ValidRangeSize[]? KeyValidRangeSizesValue
//     {
//         get => _keyValidRangeSizes;
//         set => _keyValidRangeSizes = value;
//     }
//         
//     #endregion
//     
//     
//     public abstract void GenerateIV();
//     
//     public abstract void GenerateKey();
//     
//     
//     #endregion
//     
// }