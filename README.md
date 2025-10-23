# Crypto

Данный репозиторий создан для исторической справки, учебных целей и работы с базовыми алгоритмами

## 🔐 Поддерживаемые алгоритмы

- **AES** (Advanced Encryption Standard) - современный стандарт шифрования
- **Triple DES** (3DES) - тройное шифрование DES для повышенной безопасности
- **DES** (Data Encryption Standard) - классический алгоритм блочного шифрования
- **DEAL** - блочный шифр на основе DES
- **RSA** - алгоритм с открытым ключом для шифрования и цифровых подписей

## 🚀 Использование блочных шифров

```csharp

byte[] plain = Encoding.ASCII.GetBytes("Hello, Cryptography!");

ISymmetricKeyGenerator keyGen = new AesKeyGenerator(new CryptoRandom(), 256);

ICipherOperator oper = CryptoBuilder
    .UseAes()
    .WithMode(builder => builder
        .UseMode(CipherMode.CBC)
        .WithIV(keyGen.GenerateIV()))
    .AddPadding(BlockPadding.PKCS7)
    .Build();

ICryptoParams key = keyGen.GenerateKey();

//cipher.Setup(true, key);
//byte[] encrypted = cipher.ProcessAll(data, 0 , data.Length);
//cipher.Setup(false, key);
//byte[] decrypted = cipher.ProcessAll(encrypted, 0 , encrypted.Length);

// или можете воспользоваться Crypto.Extensions

byte[] encrypted = oper.Encrypt(key, plain);

byte[] decrypted = oper.Decrypt(key, encrypted);

string decryptedText = Encoding.UTF8.GetString(decrypted);

Console.WriteLine(decryptedText);  // Hello, Cryptography!

```



