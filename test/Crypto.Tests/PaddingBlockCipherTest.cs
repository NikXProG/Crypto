using System.Diagnostics;
using System.Text;
using Crypto.Core;
using Crypto.Core.Exceptions;
using Crypto.Symmetrical;

namespace Crypto.Tests.Symmetrical
{
    
    public class PaddingBlockCipherTest
    {
        private const int BlockSize = 8;
        private readonly byte[] _plaintext = Encoding.UTF8.GetBytes("hello"); // 5 bytes

        [Theory]
        [InlineData(PaddingMode.PKCS7)]
        [InlineData(PaddingMode.ANSIX923)]
        [InlineData(PaddingMode.ISO10126)]
        public void TestPaddingModesWithDepadding(PaddingMode paddingMode)
        {
            // Arrange
            int expectedPaddedLength = 8; // 5 + 3 padding

            // Act: Calculate length
            int calculatedLength = PaddingBlockCipher.GetCiphertextLength(
                _plaintext.Length, BlockSize, paddingMode);
            
            Assert.Equal(expectedPaddedLength, calculatedLength);

            // Act: Apply padding
            byte[] padded = new byte[calculatedLength];
            int actualPaddedLength = PaddingBlockCipher.PadBlock(
                _plaintext, padded, BlockSize, paddingMode);
            
            Assert.Equal(expectedPaddedLength, actualPaddedLength);

            // Act: Remove padding
            int originalLength = PaddingBlockCipher.GetPaddingLength(
                padded, paddingMode, BlockSize);
            
            Assert.Equal(_plaintext.Length, originalLength);

            // Verify original data
            byte[] recoveredData = new byte[originalLength];
            Array.Copy(padded, recoveredData, originalLength);
            
            Assert.Equal(_plaintext, recoveredData);
        }

        [Fact]
        public void TestPaddingModeNoneExactBlockSize()
        {
            // Arrange - data that exactly fits block size
            byte[] exactBlockData = Encoding.UTF8.GetBytes("12345678"); // 8 bytes
            
            // Act & Assert
            int length = PaddingBlockCipher.GetCiphertextLength(
                exactBlockData.Length, BlockSize, PaddingMode.None);
            
            Assert.Equal(8, length);
            
            byte[] padded = new byte[length];
            int actualLength = PaddingBlockCipher.PadBlock(
                exactBlockData, padded, BlockSize, PaddingMode.None);
            
            Assert.Equal(8, actualLength);
            Assert.Equal(exactBlockData, padded[..8]);
        }

        [Fact]
        public void TestPaddingModeNonePartialBlockThrows()
        {
            // Arrange - data that doesn't fit block size
            byte[] partialData = Encoding.UTF8.GetBytes("hello"); // 5 bytes
            
            // Act & Assert
            Assert.Throws<CryptoException>(() => 
                PaddingBlockCipher.GetCiphertextLength(
                    partialData.Length, BlockSize, PaddingMode.None));
            
            byte[] padded = new byte[8];
            Assert.Throws<CryptoException>(() => 
                PaddingBlockCipher.PadBlock(
                    partialData, padded, BlockSize, PaddingMode.None));
        }

        [Fact]
        public void TestPaddingModeZeros()
        {
            // Arrange
            byte[] data = Encoding.UTF8.GetBytes("hello"); // 5 bytes
            
            // Act
            int length = PaddingBlockCipher.GetCiphertextLength(
                data.Length, BlockSize, PaddingMode.Zeros);
            
            Assert.Equal(8, length); // Still pads to full block
            
            byte[] padded = new byte[length];
            int actualLength = PaddingBlockCipher.PadBlock(
                data, padded, BlockSize, PaddingMode.Zeros);
            
            Assert.Equal(8, actualLength);
            
            // Verify data is preserved and padding is zeros
            Assert.Equal(data, padded[..5]);
            for (int i = 5; i < 8; i++)
            {
                Assert.Equal(0x00, padded[i]);
            }
            
            // Zeros padding doesn't support automatic depadding
            Assert.False(PaddingBlockCipher.DepaddingRequired(PaddingMode.Zeros));
        }

        [Fact]
        public void TestPaddingModeZerosExactBlock()
        {
            // Arrange - data that exactly fits block
            byte[] exactData = Encoding.UTF8.GetBytes("12345678"); // 8 bytes
            
            // Act
            int length = PaddingBlockCipher.GetCiphertextLength(
                exactData.Length, BlockSize, PaddingMode.Zeros);
            
            Assert.Equal(8, length); // No extra padding for exact blocks
            
            byte[] padded = new byte[length];
            int actualLength = PaddingBlockCipher.PadBlock(
                exactData, padded, BlockSize, PaddingMode.Zeros);
            
            Assert.Equal(8, actualLength);
            Assert.Equal(exactData, padded);
        }

        [Theory]
        [InlineData(PaddingMode.PKCS7)]
        [InlineData(PaddingMode.ANSIX923)]
        [InlineData(PaddingMode.ISO10126)]
        public void TestPaddingModesExactBlockSize(PaddingMode paddingMode)
        {
            // Arrange - data that exactly fits block size
            byte[] exactData = Encoding.UTF8.GetBytes("12345678"); // 8 bytes
            
            // Act
            int length = PaddingBlockCipher.GetCiphertextLength(
                exactData.Length, BlockSize, paddingMode);
            
            Assert.Equal(16, length); // Adds full block of padding
            
            byte[] padded = new byte[length];
            int actualLength = PaddingBlockCipher.PadBlock(
                exactData, padded, BlockSize, paddingMode);
            
            Assert.Equal(16, actualLength);
            
            // Verify original data is preserved
            Assert.Equal(exactData, padded[..8]);
            
            // Verify padding bytes
            switch (paddingMode)
            {
                case PaddingMode.PKCS7:
                    for (int i = 8; i < 16; i++)
                        Assert.Equal(0x08, padded[i]); // 8 bytes of padding
                    break;
                    
                case PaddingMode.ANSIX923:
                    for (int i = 8; i < 15; i++)
                        Assert.Equal(0x00, padded[i]); // 7 zeros
                    Assert.Equal(0x08, padded[15]);    // padding length
                    break;
                    
                case PaddingMode.ISO10126:
                    // Can't verify random bytes, but last byte should be padding length
                    Assert.Equal(0x08, padded[15]);
                    break;
            }
            
            // Verify depadding works
            int originalLength = PaddingBlockCipher.GetPaddingLength(
                padded, paddingMode, BlockSize);
            
            Assert.Equal(8, originalLength);
            
            byte[] recovered = new byte[originalLength];
            Array.Copy(padded, recovered, originalLength);
            Assert.Equal(exactData, recovered);
        }

        [Fact]
        public void TestDepaddingRequired()
        {
            Assert.True(PaddingBlockCipher.DepaddingRequired(PaddingMode.PKCS7));
            Assert.True(PaddingBlockCipher.DepaddingRequired(PaddingMode.ANSIX923));
            Assert.True(PaddingBlockCipher.DepaddingRequired(PaddingMode.ISO10126));
            Assert.False(PaddingBlockCipher.DepaddingRequired(PaddingMode.Zeros));
            Assert.False(PaddingBlockCipher.DepaddingRequired(PaddingMode.None));
            
            Assert.Throws<CryptoException>(() => 
                PaddingBlockCipher.DepaddingRequired((PaddingMode)999));
        }

        [Fact]
        public void TestInvalidPaddingModesThrows()
        {
            Assert.Throws<CryptoException>(() => 
                PaddingBlockCipher.GetCiphertextLength(5, 8, (PaddingMode)999));
            
            byte[] buffer = new byte[8];
            Assert.Throws<CryptoException>(() => 
                PaddingBlockCipher.PadBlock(_plaintext, buffer, 8, (PaddingMode)999));
            
            Assert.Throws<CryptoException>(() => 
                PaddingBlockCipher.GetPaddingLength(buffer, (PaddingMode)999, 8));
        }

        [Fact]
        public void TestEdgeCaseEmptyData()
        {
            byte[] emptyData = Array.Empty<byte>();
            
            // For modes that always add padding
            foreach (var mode in new[] { PaddingMode.PKCS7, PaddingMode.ANSIX923, PaddingMode.ISO10126 })
            {
                int length = PaddingBlockCipher.GetCiphertextLength(0, 8, mode);
                Assert.Equal(8, length); // Adds full block
                
                byte[] padded = new byte[length];
                int actualLength = PaddingBlockCipher.PadBlock(emptyData, padded, 8, mode);
                Assert.Equal(8, actualLength);
                
                int originalLength = PaddingBlockCipher.GetPaddingLength(padded, mode, 8);
                Assert.Equal(0, originalLength);
            }
            
            // For Zeros mode
            int zerosLength = PaddingBlockCipher.GetCiphertextLength(0, 8, PaddingMode.Zeros);
            Assert.Equal(0, zerosLength); // No padding for empty data
            
            // For None mode - should work with empty data
            int noneLength = PaddingBlockCipher.GetCiphertextLength(0, 8, PaddingMode.None);
            Assert.Equal(0, noneLength);
        }
    }
    
}

