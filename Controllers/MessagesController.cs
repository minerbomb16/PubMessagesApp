using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using PubMessagesApp.Data;
using PubMessagesApp.Models;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Ganss.Xss;
using SixLabors.ImageSharp;
using SixLabors.ImageSharp.PixelFormats;
using SixLabors.ImageSharp.Processing;

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
            sanitizer.AllowedAttributes.Remove("style");

            foreach (var message in messages)
            {
                message.Text = sanitizer.Sanitize(message.Text);
            }

            if (skip > 0)
            {
                return PartialView("_MessageListPartial", messages);
            }

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
        public async Task<IActionResult> Create(string text, IFormFile image)
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

                if (image.Length > 20 * 1024 * 1024)
                {
                    ModelState.AddModelError("Image", "Rozmiar obrazu nie może przekraczać 20 MB.");
                    return View();
                }

                try
                {
                    using (var memoryStream = new MemoryStream())
                    {
                        await image.CopyToAsync(memoryStream);
                        memoryStream.Position = 0;

                        using (var img = Image.Load<Rgba32>(memoryStream))
                        {
                            img.Metadata.ExifProfile = null; // Usuwanie metadanych

                            if (img.Width > 5000 || img.Height > 5000)
                            {
                                ModelState.AddModelError("Image", "Rozmiar obrazu jest zbyt duży.");
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

            var message = new Message
            {
                Email = User.Identity.Name,
                Text = sanitizedText,
                ImageData = imageData,
                ImageMimeType = imageMimeType,
                Timestamp = DateTime.UtcNow
            };

            _context.Messages.Add(message);
            await _context.SaveChangesAsync();

            return RedirectToAction(nameof(Index));
        }
    }
}
