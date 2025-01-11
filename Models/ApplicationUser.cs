using System.Security.Cryptography;
using Microsoft.AspNetCore.Identity;

namespace PubMessagesApp.Models
{
    public class ApplicationUser : IdentityUser
    {
        public string? PublicKey { get; set; }
        public string? EncryptedPrivateKey { get; set; }
        public string? Salt { get; set; }
        public string? SessionId { get; set; }


        public void GenerateKeys(string password)
        {
            using (var rsa = RSA.Create())
            {
                rsa.KeySize = 2048;
                PublicKey = Convert.ToBase64String(rsa.ExportRSAPublicKey());

                // Generowanie Salt
                Salt = Convert.ToBase64String(RandomNumberGenerator.GetBytes(16));

                // Szyfrowanie klucza prywatnego
                var privateKey = rsa.ExportRSAPrivateKey();
                var key = GenerateEncryptionKey(password, Salt);
                EncryptedPrivateKey = Convert.ToBase64String(AesEncrypt(privateKey, key));
            }
        }

        public byte[] DecryptPrivateKey(string password)
        {
            if (string.IsNullOrEmpty(EncryptedPrivateKey) || string.IsNullOrEmpty(Salt))
            {
                throw new InvalidOperationException("Klucz prywatny lub Salt jest pusty.");
            }

            var key = GenerateEncryptionKey(password, Salt);
            var encryptedKey = Convert.FromBase64String(EncryptedPrivateKey);
            return AesDecrypt(encryptedKey, key);
        }

        private static byte[] GenerateEncryptionKey(string password, string salt)
        {
            using var rfc2898 = new Rfc2898DeriveBytes(password, Convert.FromBase64String(salt), 100000);
            return rfc2898.GetBytes(32); // Klucz AES 256-bitowy
        }

        private static byte[] AesEncrypt(byte[] data, byte[] key)
        {
            using var aes = Aes.Create();
            aes.Key = key;
            aes.GenerateIV();
            using var encryptor = aes.CreateEncryptor();
            var encryptedData = encryptor.TransformFinalBlock(data, 0, data.Length);

            // Zapisujemy IV razem z zaszyfrowanymi danymi
            var result = new byte[aes.IV.Length + encryptedData.Length];
            Buffer.BlockCopy(aes.IV, 0, result, 0, aes.IV.Length);
            Buffer.BlockCopy(encryptedData, 0, result, aes.IV.Length, encryptedData.Length);
            return result;
        }

        private static byte[] AesDecrypt(byte[] encryptedData, byte[] key)
        {
            using var aes = Aes.Create();
            aes.Key = key;

            // Wyciągamy IV
            var iv = new byte[16];
            var ciphertext = new byte[encryptedData.Length - iv.Length];
            Buffer.BlockCopy(encryptedData, 0, iv, 0, iv.Length);
            Buffer.BlockCopy(encryptedData, iv.Length, ciphertext, 0, ciphertext.Length);

            aes.IV = iv;
            using var decryptor = aes.CreateDecryptor();
            return decryptor.TransformFinalBlock(ciphertext, 0, ciphertext.Length);
        }
    }
}
