namespace Crypto.Domain.Interfaces;

public interface ICryptoTransform
{

    ICipherOperator CreateOperator();

}