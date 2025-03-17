using System;

namespace PubMessagesApp.Models
{
    public class Message
    {
        public int Id { get; set; }
        public string Email { get; set; }
        public string Text { get; set; }
        public byte[]? ImageData { get; set; }
        public string? ImageMimeType { get; set; }
        public DateTime Timestamp { get; set; }
        public string? Signature { get; set; } 
        public bool IsSignatureValid { get; set; }
    }
}
