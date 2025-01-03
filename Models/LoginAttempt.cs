using System;

namespace PubMessagesApp.Models
{
    public class LoginAttempt
    {
        public int Id { get; set; } // Klucz główny
        public string Username { get; set; } // Nazwa użytkownika próbującego logowania
        public string IpAddress { get; set; } // Adres IP
        public bool Success { get; set; } // Czy logowanie było udane
        public string Location { get; set; } // Lokalizacja wynikająca z adresu IP
        public DateTime Timestamp { get; set; } // Data i godzina próby logowania
    }
}