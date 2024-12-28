using System.Security.Cryptography;
using System.Text;

class CryptoUtility
{
    // Symmetric Encryption using AES
    public static (byte[] encryptedData, byte[] key, byte[] iv) AESEncrypt(string plainText)
    {
        using (Aes aes = Aes.Create())
        {
            aes.GenerateKey();
            aes.GenerateIV();

            using (MemoryStream ms = new MemoryStream())
            using (CryptoStream cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
            {
                using (StreamWriter writer = new StreamWriter(cs))
                {
                    writer.Write(plainText);
                }
                return (ms.ToArray(), aes.Key, aes.IV);
            }
        }
    }

    public static string AESDecrypt(byte[] encryptedData, byte[] key, byte[] iv)
    {
        using (Aes aes = Aes.Create())
        {
            aes.Key = key;
            aes.IV = iv;

            using (MemoryStream ms = new MemoryStream(encryptedData))
            using (CryptoStream cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Read))
            using (StreamReader reader = new StreamReader(cs))
            {
                return reader.ReadToEnd();
            }
        }
    }

    // Asymmetric Encryption using RSA
    public static (byte[] encryptedData, RSAParameters privateKey, RSAParameters publicKey) RSAEncrypt(string plainText)
    {
        using (RSA rsa = RSA.Create())
        {
            RSAParameters publicKey = rsa.ExportParameters(false);
            RSAParameters privateKey = rsa.ExportParameters(true);

            byte[] encryptedData = rsa.Encrypt(Encoding.UTF8.GetBytes(plainText), RSAEncryptionPadding.Pkcs1);
            return (encryptedData, privateKey, publicKey);
        }
    }

    public static string RSADecrypt(byte[] encryptedData, RSAParameters privateKey)
    {
        using (RSA rsa = RSA.Create())
        {
            rsa.ImportParameters(privateKey);
            byte[] decryptedData = rsa.Decrypt(encryptedData, RSAEncryptionPadding.Pkcs1);
            return Encoding.UTF8.GetString(decryptedData);
        }
    }

    // Digital Signature using RSA and SHA256
    public static byte[] RSASign(string data, RSAParameters privateKey)
    {
        using (RSA rsa = RSA.Create())
        {
            rsa.ImportParameters(privateKey);
            return rsa.SignData(Encoding.UTF8.GetBytes(data), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }
    }

    public static bool RSAVerify(string data, byte[] signature, RSAParameters publicKey)
    {
        using (RSA rsa = RSA.Create())
        {
            rsa.ImportParameters(publicKey);
            return rsa.VerifyData(Encoding.UTF8.GetBytes(data), signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }
    }

    // Hashing using SHA256
    public static string ComputeSHA256Hash(string data)
    {
        using (SHA256 sha256 = SHA256.Create())
        {
            byte[] bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(data));
            StringBuilder result = new StringBuilder();

            foreach (byte b in bytes)
                result.Append(b.ToString("x2"));

            return result.ToString();
        }
    }
}

class Program
{
    static void Main()
    {
        // Original Data
        string data = "This is a secret message.";
        Console.WriteLine("Original Data: " + data);

        // Symmetric Encryption (AES)
        var (encryptedData, key, iv) = CryptoUtility.AESEncrypt(data);
        Console.WriteLine("AES Encrypted: " + Convert.ToBase64String(encryptedData));
        Console.WriteLine("AES Decrypted: " + CryptoUtility.AESDecrypt(encryptedData, key, iv));

        // Asymmetric Encryption (RSA)
        var (rsaEncryptedData, privateKey, publicKey) = CryptoUtility.RSAEncrypt(data);
        Console.WriteLine("RSA Encrypted: " + Convert.ToBase64String(rsaEncryptedData));
        Console.WriteLine("RSA Decrypted: " + CryptoUtility.RSADecrypt(rsaEncryptedData, privateKey));

        // Digital Signature
        byte[] signature = CryptoUtility.RSASign(data, privateKey);
        Console.WriteLine("Digital Signature: " + Convert.ToBase64String(signature));
        Console.WriteLine("Signature Verified: " + CryptoUtility.RSAVerify(data, signature, publicKey));

        // Hashing (SHA256)
        string hash = CryptoUtility.ComputeSHA256Hash(data);
        Console.WriteLine("SHA256 Hash: " + hash);
    }
}
