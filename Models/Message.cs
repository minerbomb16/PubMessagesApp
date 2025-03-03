﻿using System;

namespace PubMessagesApp.Models
{
    public class Message
    {
        public int Id { get; set; }
        public string Email { get; set; }
        public string Text { get; set; }
        public byte[]? ImageData { get; set; } // Nullable
        public string? ImageMimeType { get; set; } // Nullable
        public DateTime Timestamp { get; set; }
        public string? Signature { get; set; }  // Nowe pole na podpis wiadomości
        public bool IsSignatureValid { get; set; } // Pole tylko do weryfikacji (niezapisane w bazie danych)
    }
}
