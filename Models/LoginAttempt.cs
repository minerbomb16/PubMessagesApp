using System;

namespace PubMessagesApp.Models
{
    public class LoginAttempt
    {
        public int Id { get; set; }
        public string Username { get; set; }
        public string IpAddress { get; set; }
        public bool Success { get; set; }
        public string Location { get; set; }
        public DateTime Timestamp { get; set; }
    }
}