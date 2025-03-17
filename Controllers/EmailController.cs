using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using PubMessagesApp.Models;

namespace PubMessagesApp.Controllers
{
    public class EmailController : Controller
    {
        private readonly UserManager<ApplicationUser> _userManager;

        public EmailController(UserManager<ApplicationUser> userManager)
        {
            _userManager = userManager;
        }

        [HttpGet]
        public IActionResult RegistrationConfirmation()
        {
            return View();
        }

        [HttpGet]
        public async Task<IActionResult> ConfirmEmail(string userId, string token)
        {
            if (string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(token)) return BadRequest("Nieprawidłowe dane");

            token = System.Net.WebUtility.UrlDecode(token);
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null) return NotFound("Nie znaleziono użytkownika.");

            var result = await _userManager.ConfirmEmailAsync(user, token);
            if (result.Succeeded) return View("EmailConfirmed");
            return BadRequest("Potwierdzenie e-maila nie powiodło się.");
        }
    }
}
