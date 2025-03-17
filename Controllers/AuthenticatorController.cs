using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using PubMessagesApp.Models;
using System.Text;
using OtpNet;
using Microsoft.AspNetCore.Authorization;
using System.Text.RegularExpressions;

namespace PubMessagesApp.Controllers
{
    public class AuthenticatorController : Controller
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;

        public AuthenticatorController(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager)
        {
            _userManager = userManager;
            _signInManager = signInManager;
        }

        [HttpGet]
        public async Task<IActionResult> VerifyGoogleAuthenticator()
        {
            var userId = HttpContext.Session.GetString("UserId");
            if (string.IsNullOrEmpty(userId))
            {
                AccountController.ClearSensitiveSessionData(HttpContext.Session);
                return RedirectToAction("Login");
            }

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                AccountController.ClearSensitiveSessionData(HttpContext.Session);
                return RedirectToAction("Login");
            }
            return View("VerifyGoogleAuthenticator");
        }

        [HttpPost]
        public async Task<IActionResult> VerifyGoogleAuthenticator(string code)
        {
            var userId = HttpContext.Session.GetString("UserId");
            if (string.IsNullOrEmpty(userId))
            {
                AccountController.ClearSensitiveSessionData(HttpContext.Session);
                return RedirectToAction("Login");
            }

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                AccountController.ClearSensitiveSessionData(HttpContext.Session);
                return RedirectToAction("Login");
            }
            if (string.IsNullOrWhiteSpace(user.GoogleAuthenticatorSecret)) return RedirectToAction("GoogleAuthenticatorSetup");

            var password = HttpContext.Session.GetString("UserPassword");
            if (string.IsNullOrEmpty(password))
            {
                AccountController.ClearSensitiveSessionData(HttpContext.Session);
                return RedirectToAction("Login");
            }

            var decryptedSecret = user.DecryptGoogleAuthenticatorSecret(password);
            var secretKey = Base32Encoding.ToBytes(decryptedSecret);
            var totp = new Totp(secretKey);
            if (string.IsNullOrEmpty(code) || !Regex.IsMatch(code, @"^\d{6}$") || !totp.VerifyTotp(code, out _))
            {
                await AccountController.CreateDelay(1000);
                ModelState.AddModelError(string.Empty, "Nieprawidłowy kod.");
                return View("VerifyGoogleAuthenticator");
            }

            user.IsGoogleAuthenticatorConfigured = true;
            await _signInManager.SignInAsync(user, isPersistent: false);
            user.SessionId = Guid.NewGuid().ToString();
            await _userManager.UpdateAsync(user);

            HttpContext.Response.Cookies.Append("SessionId", user.SessionId, new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Strict,
                Expires = DateTime.UtcNow.AddHours(1)
            });

            AccountController.ClearSensitiveSessionData(HttpContext.Session);
            return RedirectToAction("Index", "Messages");
        }

        [HttpGet]
        public async Task<IActionResult> GoogleAuthenticatorSetup()
        {
            var userId = HttpContext.Session.GetString("UserId");
            if (string.IsNullOrEmpty(userId))
            {
                AccountController.ClearSensitiveSessionData(HttpContext.Session);
                return RedirectToAction("Login");
            }
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                AccountController.ClearSensitiveSessionData(HttpContext.Session);
                return RedirectToAction("Login");
            }

            var password = HttpContext.Session.GetString("UserPassword");
            if (string.IsNullOrEmpty(password))
            {
                AccountController.ClearSensitiveSessionData(HttpContext.Session);
                return RedirectToAction("Login");
            }

            user.GenerateGoogleAuthenticatorSecret(password);
            await _userManager.UpdateAsync(user);
            var decryptedSecret = user.DecryptGoogleAuthenticatorSecret(password);
            return View("SetupGoogleAuthenticator", decryptedSecret);
        }

        [Authorize]
        [HttpGet]
        public IActionResult VerifyChangePassword()
        {
            var userId = HttpContext.Session.GetString("UserId");
            if (string.IsNullOrEmpty(userId))
            {
                AccountController.ClearSensitiveSessionData(HttpContext.Session);
                return RedirectToAction("Login");
            }
            return View();
        }

        [Authorize]
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> VerifyChangePasswordCode(string code)
        {
            var userId = HttpContext.Session.GetString("UserId");
            if (string.IsNullOrEmpty(userId))
            {
                AccountController.ClearSensitiveSessionData(HttpContext.Session);
                return RedirectToAction("Login");
            }

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                AccountController.ClearSensitiveSessionData(HttpContext.Session);
                return RedirectToAction("Login");
            }
            
            var password = HttpContext.Session.GetString("UserPassword");
            if (string.IsNullOrEmpty(password))
            {
                AccountController.ClearSensitiveSessionData(HttpContext.Session);
                return RedirectToAction("Login");
            }
            if (string.IsNullOrWhiteSpace(user.GoogleAuthenticatorSecret)) return RedirectToAction("GoogleAuthenticatorSetup");

            var decryptedSecret = user.DecryptGoogleAuthenticatorSecret(password);
            var secretKey = Base32Encoding.ToBytes(decryptedSecret);
            var totp = new Totp(secretKey);
            if (string.IsNullOrEmpty(code) || !Regex.IsMatch(code, @"^\d{6}$") || !totp.VerifyTotp(code, out _))
            {
                await AccountController.CreateDelay(1000);
                ModelState.AddModelError(string.Empty, "Nieprawidłowy kod.");
                return View("VerifyChangePassword");
            }

            var newPassword = HttpContext.Session.GetString("NewPassword");
            var decryptedPrivateKey = user.DecryptPrivateKey(password);
            var encryptionKey = ApplicationUser.GenerateEncryptionKey(newPassword, user.Salt);
            user.EncryptedPrivateKey = Convert.ToBase64String(ApplicationUser.AesEncrypt(decryptedPrivateKey, encryptionKey));
            user.GoogleAuthenticatorSecret = Convert.ToBase64String(ApplicationUser.AesEncrypt(Encoding.UTF8.GetBytes(decryptedSecret), encryptionKey));
            var result = await _userManager.ChangePasswordAsync(user, password, newPassword);

            if (result.Succeeded) return RedirectToAction("Index", "Messages");
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }
            AccountController.ClearSensitiveSessionData(HttpContext.Session);
            return View("VerifyChangePassword");
        }
    }
}
