﻿using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using PubMessagesApp.Data;
using PubMessagesApp.Models;
using System.Security.Cryptography;
using System.Text;
using Ganss.Xss;
using SixLabors.ImageSharp;
using SixLabors.ImageSharp.PixelFormats;
using Microsoft.AspNetCore.Identity;

namespace PubMessagesApp.Controllers
{
    public class MessagesController : Controller
    {
        private readonly ApplicationDbContext _context;

        public MessagesController(ApplicationDbContext context)
        {
            _context = context;
        }

        [HttpGet]
        public IActionResult Index(int skip = 0, int take = 10)
        {
            var messages = _context.Messages
                .OrderByDescending(m => m.Timestamp)
                .Skip(skip)
                .Take(take)
                .ToList();

            var sanitizer = new HtmlSanitizer();
            sanitizer.AllowedTags.Clear();
            sanitizer.AllowedAttributes.Clear();
            sanitizer.AllowedTags.Add("b");
            sanitizer.AllowedTags.Add("i");
            sanitizer.AllowedTags.Add("br");

            foreach (var message in messages)
            {
                message.Text = sanitizer.Sanitize(message.Text);
                message.IsSignatureValid = VerifySignature(message);
            }

            if (skip > 0)  return PartialView("_MessageListPartial", messages);
            return View(messages);
        }

        [Authorize]
        [HttpGet]
        public IActionResult Create()
        {
            return View();
        }

        [Authorize]
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create(string text, IFormFile image, string signMessagePassword)
        {
            if (string.IsNullOrWhiteSpace(text))
            {
                ModelState.AddModelError("Text", "Treść wiadomości jest wymagana.");
                return View();
            }

            var sanitizer = new HtmlSanitizer();
            string sanitizedText = sanitizer.Sanitize(text);
            byte[] imageData = null;
            string imageMimeType = null;

            if (image != null)
            {
                if (image.ContentType != "image/png" && image.ContentType != "image/jpeg")
                {
                    ModelState.AddModelError("Image", "Obsługiwane są tylko obrazy w formacie PNG lub JPEG.");
                    return View();
                }

                if (image.Length > 5 * 1024 * 1024)
                {
                    ModelState.AddModelError("Image", "Rozmiar obrazu nie może przekraczać 5 MB.");
                    return View();
                }

                try
                {
                    using (var memoryStream = new MemoryStream())
                    {
                        await image.CopyToAsync(memoryStream);
                        memoryStream.Position = 0;

                        if (!FileTypeValidator.IsPng(memoryStream.ToArray()) && !FileTypeValidator.IsJpeg(memoryStream.ToArray()))
                        {
                            ModelState.AddModelError("Image", "Przesłany plik nie jest prawidłowym obrazem.");
                            return View();
                        }

                        using (var img = Image.Load<Rgba32>(memoryStream))
                        {
                            img.Metadata.ExifProfile = null;

                            if (img.Width > 5000 || img.Height > 5000)
                            {
                                ModelState.AddModelError("Image", "Rozmiar obrazu jest zbyt duży.");
                                return View();
                            }
                            else if (img.Width < 50 || img.Height < 50)
                            {
                                ModelState.AddModelError("Image", "Rozmiar obrazu jest zbyt mały.");
                                return View();
                            }

                            using (var outputStream = new MemoryStream())
                            {
                                if (image.ContentType == "image/jpeg")
                                {
                                    img.SaveAsJpeg(outputStream);
                                    imageMimeType = "image/jpeg";
                                }
                                else if (image.ContentType == "image/png")
                                {
                                    img.SaveAsPng(outputStream);
                                    imageMimeType = "image/png";
                                }

                                imageData = outputStream.ToArray();
                            }
                        }
                    }
                }
                catch
                {
                    ModelState.AddModelError("Image", "Przesłany plik nie jest prawidłowym obrazem.");
                    return View();
                }
            }

            if (!HttpContext.Request.Cookies.TryGetValue("SessionId", out var sessionId) || string.IsNullOrEmpty(sessionId))return Unauthorized("Sesja nieprawidłowa lub wygasła.");

            var user = _context.Users.FirstOrDefault(u => u.UserName == User.Identity.Name);
            if (user == null || user.SessionId != sessionId) return Unauthorized("Nieprawidłowe ciasteczko.");

            var message = new Message
            {
                Email = User.Identity.Name,
                Text = sanitizedText,
                ImageData = imageData,
                ImageMimeType = imageMimeType,
                Timestamp = DateTime.UtcNow
            };

            if (!string.IsNullOrEmpty(signMessagePassword))
            {
                if (user == null || string.IsNullOrEmpty(user.EncryptedPrivateKey)) return BadRequest("Nie brak użytkownika lub brak klucza prywatnego.");

                try
                {
                    var privateKeyBytes = user.DecryptPrivateKey(signMessagePassword);
                    using var rsa = RSA.Create();
                    rsa.ImportRSAPrivateKey(privateKeyBytes, out _);
                    var messageBytes = Encoding.UTF8.GetBytes(sanitizedText);
                    using var sha256 = SHA256.Create();
                    var messageHash = sha256.ComputeHash(messageBytes);
                    var signature = rsa.SignData(messageHash, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                    message.Signature = Convert.ToBase64String(signature);
                }
                catch (CryptographicException)
                {
                    ModelState.AddModelError("signMessagePassword", "Nieprawidłowe hasło.");
                    return View();
                }
            }

            _context.Messages.Add(message);
            await _context.SaveChangesAsync();

            return RedirectToAction(nameof(Index));
        }

        private bool VerifySignature(Message message)
        {
            var user = _context.Users.FirstOrDefault(u => u.Email == message.Email);
            if (user == null || string.IsNullOrEmpty(user.PublicKey) || string.IsNullOrEmpty(message.Signature))
            {
                return false;
            }

            using (var rsa = RSA.Create())
            {
                rsa.ImportRSAPublicKey(Convert.FromBase64String(user.PublicKey), out _);
                var messageBytes = Encoding.UTF8.GetBytes(message.Text);
                using var sha256 = SHA256.Create();
                var messageHash = sha256.ComputeHash(messageBytes);
                var signatureBytes = Convert.FromBase64String(message.Signature);
                return rsa.VerifyData(messageHash, signatureBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            }
        }

        [Authorize]
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ValidatePassword([FromBody] ValidatePasswordRequest request)
        {
            await AccountController.CreateDelay(1000);
            var user = _context.Users.FirstOrDefault(u => u.UserName == User.Identity.Name);
            if (user == null) return Json(new { success = false });

            var passwordHasher = new PasswordHasher<ApplicationUser>();
            var result = passwordHasher.VerifyHashedPassword(user, user.PasswordHash, request.Password);

            if (result == PasswordVerificationResult.Success) return Json(new { success = true });
            return Json(new { success = false });
        }

        public class ValidatePasswordRequest
        {
            public string Password { get; set; }
        }
    }

    public static class FileTypeValidator
    {
        private static readonly byte[] JpegHeader = new byte[] { 0xFF, 0xD8, 0xFF };
        private static readonly byte[] PngHeader = new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A };

        public static bool IsJpeg(byte[] fileContent)
        {
            if (fileContent == null || fileContent.Length < JpegHeader.Length) return false;
            return fileContent[..JpegHeader.Length].SequenceEqual(JpegHeader);
        }

        public static bool IsPng(byte[] fileContent)
        {
            if (fileContent == null || fileContent.Length < PngHeader.Length) return false;
            return fileContent[..PngHeader.Length].SequenceEqual(PngHeader);
        }
    }
}
