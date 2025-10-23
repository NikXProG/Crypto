namespace Crypto.Domain.Interfaces;

public interface IDes
{

    public void DesFunc(int[] wKey, ref uint hi32, ref uint lo32);

    public int[] TransformKey(bool encrypting, byte[] key);


}