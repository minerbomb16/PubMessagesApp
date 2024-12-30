using System.Security.Cryptography;
using Microsoft.AspNetCore.Identity;

namespace PubMessagesApp.Models
{
    public class ApplicationUser : IdentityUser
    {
        // Pola na klucze RSA
        public string? PublicKey { get; set; }
        public string? PrivateKey { get; set; }

        // Metoda do generowania kluczy RSA
        public void GenerateKeys()
        {
            using (var rsa = RSA.Create())
            {
                rsa.KeySize = 2048;
                PublicKey = Convert.ToBase64String(rsa.ExportRSAPublicKey());
                PrivateKey = Convert.ToBase64String(rsa.ExportRSAPrivateKey());
            }
        }
    }
}
