
using System.Security.Cryptography;



class Program
{
    static void Main()
    {
        Console.WriteLine("Bienvenue dans l'application de chiffrement et de déchiffrement !");

        while (true)
        {
            Console.WriteLine("Choisissez une option :");
            Console.WriteLine("1. Chiffrer un message");
            Console.WriteLine("2. Déchiffrer un message");
            Console.WriteLine("3. Quitter");

            string choice = Console.ReadLine();

            switch (choice)
            {
                case "1":
                    EncryptMessage();
                    break;
                case "2":
                    DecryptMessage();
                    break;
                case "3":
                    Environment.Exit(0);
                    break;
                default:
                    Console.WriteLine("Option non valide. Veuillez réessayer.");
                    break;
            }
        }
    }
    static void EncryptMessage()
    {
        Console.Write("Entrez le message à chiffrer : ");
        string message = Console.ReadLine();

        using (Aes aesAlg = Aes.Create())
        {
            aesAlg.GenerateKey();
            aesAlg.GenerateIV();

            byte[] key = aesAlg.Key;
            byte[] iv = aesAlg.IV;

            byte[] encryptedData = EncryptStringToBytes_Aes(message, key, iv);

            Console.WriteLine("Message chiffré : " + Convert.ToBase64String(encryptedData));
            Console.WriteLine("Clé : " + Convert.ToBase64String(key));
            Console.WriteLine("IV : " + Convert.ToBase64String(iv));
        }
    }

    static void DecryptMessage()
    {
        Console.Write("Entrez le message chiffré : ");
        string encryptedMessage = Console.ReadLine();
        Console.Write("Entrez la clé : ");
        string keyInput = Console.ReadLine();
        Console.Write("Entrez l'IV : ");
        string ivInput = Console.ReadLine();

        byte[] key = Convert.FromBase64String(keyInput);
        byte[] iv = Convert.FromBase64String(ivInput);
        byte[] encryptedData = Convert.FromBase64String(encryptedMessage);

        string decryptedMessage = DecryptStringFromBytes_Aes(encryptedData, key, iv);

        Console.WriteLine("Message déchiffré : " + decryptedMessage);
    }

    static byte[] EncryptStringToBytes_Aes(string plainText, byte[] key, byte[] iv)
    {
        byte[] encrypted;
        using (Aes aesAlg = Aes.Create())
        {
            aesAlg.Key = key;
            aesAlg.IV = iv;

            ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

            using (MemoryStream msEncrypt = new MemoryStream())
            {
                using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                {
                    using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                    {
                        swEncrypt.Write(plainText);
                    }
                }
                encrypted = msEncrypt.ToArray();
            }
        }
        return encrypted;
    }

    static string DecryptStringFromBytes_Aes(byte[] cipherText, byte[] key, byte[] iv)
    {
        string plaintext = null;
        using (Aes aesAlg = Aes.Create())
        {
            aesAlg.Key = key;
            aesAlg.IV = iv;

            ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

            using (MemoryStream msDecrypt = new MemoryStream(cipherText))
            {
                using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                {
                    using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                    {
                        plaintext = srDecrypt.ReadToEnd();
                    }
                }
            }
        }
        return plaintext;
    }
}
