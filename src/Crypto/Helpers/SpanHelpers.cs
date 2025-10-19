namespace Crypto.Helpers;

internal static class SpanHelpers
{
    internal static Span<T> FromNullable<T>(T[]? array)
    {
        return array == null ? Span<T>.Empty : array.AsSpan();
    }
    
    internal static Span<T> FromNullable<T>(T[]? array, int start)
    {
        return array == null ? Span<T>.Empty : array.AsSpan(start);
    }

}