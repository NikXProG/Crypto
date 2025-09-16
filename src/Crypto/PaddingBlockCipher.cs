using System.Security.Cryptography;
using Crypto.Core.Exceptions;
using PaddingMode = Crypto.Core.PaddingMode;

namespace Crypto.Symmetrical;

public static class PaddingBlockCipher
{

    public static int GetCiphertextLength(int plaintextLength, int paddingSizeInBytes, PaddingMode paddingMode)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(plaintextLength);

        //divisor and factor are same and won't overflow.
        int wholeBlocks = Math.DivRem(plaintextLength, paddingSizeInBytes, out int remainder) * paddingSizeInBytes;

        switch (paddingMode)
        {
            case PaddingMode.None when (remainder != 0):
                throw new CryptoException("Padding mode is invalid.");
            case PaddingMode.None:
            case PaddingMode.Zeros when (remainder == 0):
                return plaintextLength;
            case PaddingMode.Zeros:
            case PaddingMode.PKCS7:
            case PaddingMode.ANSIX923:
            case PaddingMode.ISO10126:
                return checked(wholeBlocks + paddingSizeInBytes);
            default:
                throw new CryptoException("Unknown padding mode.");
        }
    }

    public static int PadBlock(ReadOnlySpan<byte> block, Span<byte> destination, int paddingSizeInBytes, PaddingMode paddingMode)
    {
        int count = block.Length;
        int paddingRemainder = count % paddingSizeInBytes;
        int padBytes = paddingSizeInBytes - paddingRemainder;

        switch (paddingMode)
        {
            case PaddingMode.None when (paddingRemainder != 0):
                throw new CryptoException("Partial block requires padding");

            case PaddingMode.None:
                if (destination.Length < count)
                {
                    throw new ArgumentException("block is short.", nameof(destination));
                }

                block.CopyTo(destination);
                return count;

            // [Data] + [00...00] + [byte padding]
            // Example: "hello" → "hello" + 0x00 0x00 0x03
            case PaddingMode.ANSIX923:
                int ansiSize = count + padBytes;

                if (destination.Length < ansiSize)
                {
                    throw new ArgumentException("block is short.", nameof(destination));
                }

                block.CopyTo(destination);
                destination.Slice(count, padBytes - 1).Clear();
                destination[count + padBytes - 1] = (byte)padBytes;
                return ansiSize;

            // [Data] + [random] + [byte padding]
            // Example: "hello" → "hello" + 0xAB 0xCD 0x03
            case PaddingMode.ISO10126:
                int isoSize = count + padBytes;

                if (destination.Length < isoSize)
                {
                    throw new ArgumentException("block is short.", nameof(destination));
                }

                block.CopyTo(destination);
                RandomNumberGenerator.Fill(destination.Slice(count, padBytes - 1));
                destination[count + padBytes - 1] = (byte)padBytes;
                return isoSize;

            // [Data] + [byte padding] * N
            // Example: "hello" (5 byte) → "hello" + 0x03 0x03 0x03
            case PaddingMode.PKCS7:
                int pkcsSize = count + padBytes;

                if (destination.Length < pkcsSize)
                {
                    throw new ArgumentException("block is short.", nameof(destination));
                }

                block.CopyTo(destination);
                destination.Slice(count, padBytes).Fill((byte)padBytes);
                return pkcsSize;

            // [Data] + [00...00]
            // "hello" → "hello" + 0x00 0x00 0x00
            case PaddingMode.Zeros:
                if (padBytes == paddingSizeInBytes)
                {
                    padBytes = 0;
                }

                int zeroSize = count + padBytes;

                if (destination.Length < zeroSize)
                {
                    throw new ArgumentException("block is short.", nameof(destination));
                }

                block.CopyTo(destination);
                destination.Slice(count, padBytes).Clear();
                return zeroSize;

            default:
                throw new CryptoException("Unknown padding mode.");
        }
    }

    public static bool DepaddingRequired(PaddingMode padding)
    {
        // Some padding modes encode sufficient information to allow for automatic depadding to happen.
        switch (padding)
        {
            case PaddingMode.PKCS7:
            case PaddingMode.ANSIX923:
            case PaddingMode.ISO10126:
                return true;
            case PaddingMode.Zeros:
            case PaddingMode.None:
                return false;
            default:
                throw new CryptoException("Unknown padding mode.");
        }
    }

    public static int GetPaddingLength(ReadOnlySpan<byte> block, PaddingMode paddingMode, int blockSize)
    {
        int padBytes;

        // See PadBlock for a description of the padding modes.
        switch (paddingMode)
        {
            case PaddingMode.ANSIX923:
                padBytes = block[^1];

                // Verify the amount of padding is reasonable
                if (padBytes <= 0 || padBytes > blockSize)
                {
                    throw new CryptoException("Invalid padding mode.");
                }

                // Verify that all the padding bytes are 0s
                if (block.Slice(block.Length - padBytes, padBytes - 1).ContainsAnyExcept((byte)0))
                {
                    throw new CryptoException("Invalid padding mode.");
                }

                break;

            case PaddingMode.ISO10126:
                padBytes = block[^1];

                // Verify the amount of padding is reasonable
                if (padBytes <= 0 || padBytes > blockSize)
                {
                    throw new CryptoException("Invalid padding mode.");
                }

                // Since the padding consists of random bytes, we cannot verify the actual pad bytes themselves
                break;

            case PaddingMode.PKCS7:
                padBytes = block[^1];

                // Verify the amount of padding is reasonable
                if (padBytes <= 0 || padBytes > blockSize)
                    throw new CryptoException("Invalid padding mode.");

                // Verify all the padding bytes match the amount of padding
                for (int i = block.Length - padBytes; i < block.Length - 1; i++)
                {
                    if (block[i] != padBytes)
                        throw new CryptoException("Invalid padding mode.");
                }

                break;

            // We cannot remove Zeros padding because we don't know if the zeros at the end of the block
            // belong to the padding or the plaintext itself.
            case PaddingMode.Zeros:
            case PaddingMode.None:
                padBytes = 0;
                break;

            default:
                throw new CryptoException("Unknown padding mode.");
        }

        return block.Length - padBytes;
    }

}