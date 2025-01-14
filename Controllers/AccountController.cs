using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using PubMessagesApp.Data;
using PubMessagesApp.Models;
using PubMessagesApp.ViewModels;
using MaxMind.GeoIP2;
using Microsoft.AspNetCore.Hosting;
using System.Net;
using Newtonsoft.Json;
using Microsoft.AspNetCore.Authorization;
using OtpNet;
using System.Security.Cryptography;
using System.Text;
using QRCoder;
using System.Drawing;


namespace PubMessagesApp.Controllers
{
    public class AccountController : Controller
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly ApplicationDbContext _context;
        private readonly IWebHostEnvironment _env;

        public AccountController(
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            ApplicationDbContext context,
            IWebHostEnvironment env)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _context = context;
            _env = env;
        }

        public async Task<IActionResult> Login(LoginViewModel model)
        {
            if (!ModelState.IsValid) return View(model);

            const int maxAttempts = 5;
            const int lockoutMinutes = 5;

            await Task.Delay(1000);

            var user = await _userManager.FindByEmailAsync(model.Email);
            var ipAddress = !string.IsNullOrEmpty(model.UserIp) ? model.UserIp : "Unknown";
            var timestamp = DateTime.Now;
            bool loginSuccess = false;
            string dbPath = Path.Combine(_env.ContentRootPath, "Data", "country.mmdb");
            string location = "Unknown";

            try
            {
                if (!System.IO.File.Exists(dbPath))
                {
                    throw new FileNotFoundException("Plik country.mmdb nie został znaleziony.", dbPath);
                }

                if (!IPAddress.TryParse(ipAddress, out IPAddress ip))
                {
                    throw new FormatException("Adres IP ma nieprawidłowy format.");
                }

                using (var reader = new MaxMind.Db.Reader(dbPath))
                {
                    var result = reader.Find<dynamic>(ip);
                    if (result != null)
                    {
                        string countryCode = result["country"] ?? "Unknown";
                        string countryName = result["country_name"] ?? "Unknown";
                        string continentCode = result["continent"] ?? "Unknown";
                        string continentName = result["continent_name"] ?? "Unknown";
                        location = $"{countryName}, {continentName}";
                    }
                }
            }
            catch (Exception ex)
            {
                location = "Unknown";
            }

            if (user != null)
            {
                // Sprawdzenie blokady konta
                var lockoutEnd = await _userManager.GetLockoutEndDateAsync(user);
                if (lockoutEnd.HasValue && lockoutEnd.Value > DateTimeOffset.UtcNow)
                {
                    var remainingLockout = lockoutEnd.Value - DateTimeOffset.UtcNow;
                    ViewData["Error"] = $"Konto jest zablokowane. Spróbuj ponownie za {remainingLockout.Minutes} min {remainingLockout.Seconds} s.";
                    //loginSuccess = false;
                }
                else
                {
                    var result = await _signInManager.CheckPasswordSignInAsync(user, model.Password, lockoutOnFailure: false);
                    var loginAttempt = new LoginAttempt
                    {
                        Username = model.Email,
                        IpAddress = ipAddress,
                        Success = result.Succeeded,
                        Location = location,
                        Timestamp = timestamp
                    };
                    _context.LoginAttempts.Add(loginAttempt);
                    await _context.SaveChangesAsync();
                    if (result.Succeeded)
                    {
                        await _userManager.ResetAccessFailedCountAsync(user);
                        TempData["UserPassword"] = model.Password;
                        TempData["UserId"] = user.Id;
                        if (!user.IsGoogleAuthenticatorConfigured)
                        {
                            return RedirectToAction("GoogleAuthenticatorSetup", "Account");
                        }

                        return RedirectToAction("VerifyGoogleAuthenticator", "Account");
                    }
                    else
                    {
                        // Zwiększ liczbę nieudanych prób
                        await _userManager.AccessFailedAsync(user);
                    }
                }
            }
            else
            {
                ViewData["Error"] = "Nieprawidłowe dane logowania.";
                return View(model);
            }

            // Odczekaj, aż zmiana liczby prób zostanie zaktualizowana
            var failedAttempts = await _userManager.GetAccessFailedCountAsync(user);

            // Obliczenie pozostałych prób
            var remainingAttempts = maxAttempts - failedAttempts - 1;

            if (remainingAttempts <= 0)
            {
                // Blokada konta po przekroczeniu maksymalnej liczby prób
                await _userManager.SetLockoutEndDateAsync(user, DateTimeOffset.UtcNow.AddMinutes(lockoutMinutes));
                await _userManager.ResetAccessFailedCountAsync(user);
                ViewData["Error"] = $"Konto zostało zablokowane na {lockoutMinutes} minut.";
            }
            else
            {
                // Wyświetl informację o pozostałych próbach
                ViewData["Error"] = $"Nieprawidłowe dane logowania. Pozostało prób: {remainingAttempts}.";
            }

            return View(model);
        }

        public IActionResult LoginHistory()
        {
            var username = User.Identity?.Name;
            if (string.IsNullOrEmpty(username))
            {
                return RedirectToAction("Login");
            }

            var loginAttempts = _context.LoginAttempts
                .Where(l => l.Username == username)
                .OrderByDescending(l => l.Timestamp)
                .ToList();

            return View(loginAttempts);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterViewModel model)
        {
            if (!ModelState.IsValid) return View(model);

            var existingUser = await _userManager.FindByEmailAsync(model.Email);

            // Jeśli użytkownik istnieje, ale e-mail nie został potwierdzony, usuń go
            if (existingUser != null && !await _userManager.IsEmailConfirmedAsync(existingUser))
            {
                var result = await _userManager.DeleteAsync(existingUser);
                if (!result.Succeeded)
                {
                    return View(model);
                }
            }
            else if (existingUser != null)
            {
                ViewData["Error"] = "Konto na podany adres email już istnieje.";
                return View(model);
            }

            var user = new ApplicationUser { UserName = model.Email, Email = model.Email, IsGoogleAuthenticatorConfigured = false };
            user.GenerateKeys(model.Password);
            var createResult = await _userManager.CreateAsync(user, model.Password);
            user.TwoFactorEnabled = false;
            await _userManager.UpdateAsync(user);

            if (createResult.Succeeded)
            {
                var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                var encodedToken = System.Net.WebUtility.UrlEncode(token);
                var confirmationLink = Url.Action(nameof(ConfirmEmail), "Account",
                    new { userId = user.Id, token = encodedToken }, Request.Scheme);

                TempData["Email"] = model.Email;
                TempData["ConfirmationLink"] = confirmationLink;

                return RedirectToAction(nameof(RegistrationConfirmation));
            }

            foreach (var error in createResult.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }

            return View(model);
        }

        [HttpGet]
        public IActionResult RegistrationConfirmation()
        {
            return View();
        }

        [HttpGet]
        public async Task<IActionResult> ConfirmEmail(string userId, string token)
        {

            if (string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(token))
            {
                return BadRequest("Nieprawidłowe dane potwierdzające: brak userId lub token.");
            }

            // Dekodowanie tokenu URL
            token = System.Net.WebUtility.UrlDecode(token);

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return NotFound("Nie znaleziono użytkownika.");
            }

            var result = await _userManager.ConfirmEmailAsync(user, token);
            if (result.Succeeded)
            {
                return View("EmailConfirmed");
            }

            return BadRequest("Potwierdzenie e-maila nie powiodło się.");
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user != null)
            {
                user.SessionId = null;
                await _userManager.UpdateAsync(user);
            }

            HttpContext.Response.Cookies.Delete("SessionId");
            await _signInManager.SignOutAsync();
            return RedirectToAction("Index", "Messages");
        }

        [HttpGet]
        public IActionResult Login()
        {
            return View();
        }

        [HttpGet]
        public IActionResult Register()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult SaveUserIp([FromBody] dynamic request)
        {
            string userIp = request.userIp?.ToString();

            if (string.IsNullOrEmpty(userIp))
            {
                return Json(new { success = false, error = "Adres IP jest wymagany." });
            }

            HttpContext.Items["UserIp"] = userIp;
            Console.WriteLine($"Przypisano adres IP: {userIp}");

            return Json(new { success = true });
        }

        [HttpGet]
        public async Task<IActionResult> VerifyGoogleAuthenticator()
        {
            var userId = TempData["UserId"]?.ToString();
            if (string.IsNullOrEmpty(userId))
            {
                TempData["Error"] = "Brak użytkownika do weryfikacji.";
                return RedirectToAction("Login");
            }

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                TempData["Error"] = "Nie znaleziono użytkownika.";
                return RedirectToAction("Login");
            }
            TempData["UserId"] = userId;
            return View("VerifyGoogleAuthenticator");
        }

        [HttpPost]
        public async Task<IActionResult> VerifyGoogleAuthenticator(string code)
        {
            var userId = TempData["UserId"]?.ToString();
            if (string.IsNullOrEmpty(userId))
            {
                TempData["Error"] = "Brak użytkownika do weryfikacji.";
                return RedirectToAction("Login");
            }

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                TempData["Error"] = "Nie znaleziono użytkownika.";
                return RedirectToAction("Login");
            }

            if (string.IsNullOrWhiteSpace(user.GoogleAuthenticatorSecret))
            {
                TempData["Error"] = "Google Authenticator nie został skonfigurowany.";
                return RedirectToAction("GoogleAuthenticatorSetup");
            }

            // Decrypt secret
            var password = TempData["UserPassword"]?.ToString();
            if (string.IsNullOrEmpty(password))
            {
                TempData["Error"] = "Hasło użytkownika jest wymagane.";
                return RedirectToAction("Login");
            }

            var decryptedSecret = user.DecryptGoogleAuthenticatorSecret(password);

            var secretKey = Base32Encoding.ToBytes(decryptedSecret);
            var totp = new Totp(secretKey);
            if (!totp.VerifyTotp(code, out _))
            {
                ModelState.AddModelError(string.Empty, "Nieprawidłowy kod.");
                TempData["UserPassword"] = password;
                TempData["UserId"] = userId;
                return View("VerifyGoogleAuthenticator");
            }

            // Successful verification
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

            return RedirectToAction("Index", "Messages");
        }

        [HttpGet]
        public async Task<IActionResult> GoogleAuthenticatorSetup()
        {
            var userId = TempData["UserId"]?.ToString();
            if (string.IsNullOrEmpty(userId))
            {
                TempData["Error"] = "Brak użytkownika do konfiguracji.";
                return RedirectToAction("Login");
            }

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                TempData["Error"] = "Nie znaleziono użytkownika.";
                return RedirectToAction("Login");
            }

            var password = TempData["UserPassword"] as string;
            if (string.IsNullOrEmpty(password))
            {
                TempData["Error"] = "Hasło użytkownika jest wymagane.";
                return RedirectToAction("Login");
            }

            user.GenerateGoogleAuthenticatorSecret(password);
            await _userManager.UpdateAsync(user);

            var decryptedSecret = user.DecryptGoogleAuthenticatorSecret(password);
            var qrCodeUri = $"otpauth://totp/PubMessagesApp:{user.Email}?secret={decryptedSecret}&issuer=PubMessagesApp";
            TempData["QrCodeUri"] = qrCodeUri;
            TempData["ManualCode"] = decryptedSecret;
            TempData["UserPassword"] = password;
            TempData["UserId"] = userId;
            return View("SetupGoogleAuthenticator");
        }


        public IActionResult GenerateQrCode(string qrCodeUri)
        {
            try
            {
                using var qrGenerator = new QRCodeGenerator();
                using var qrCodeData = qrGenerator.CreateQrCode(qrCodeUri, QRCodeGenerator.ECCLevel.Q);
                var qrCode = new BitmapByteQRCode(qrCodeData);
                var qrCodeImage = qrCode.GetGraphic(20);

                // Konwertuj bajty obrazu na Bitmap i przeskaluj do 500x500
                using var ms = new MemoryStream(qrCodeImage);
                using var originalBitmap = new Bitmap(ms);
                using var resizedBitmap = new Bitmap(originalBitmap, new Size(500, 500));

                using var outputStream = new MemoryStream();
                resizedBitmap.Save(outputStream, System.Drawing.Imaging.ImageFormat.Png);
                return File(outputStream.ToArray(), "image/png");
            }
            catch (Exception ex)
            {
                // Jeśli wystąpi błąd, wyświetl zwykły kod tekstowy
                Console.WriteLine($"Błąd generowania kodu QR: {ex.Message}");
                return Content("Unable to generate QR code. Use this manual code: " + ExtractManualCode(qrCodeUri), "text/plain");
            }
        }

        // Metoda pomocnicza do wyodrębniania kodu ręcznego z URI
        private string ExtractManualCode(string qrCodeUri)
        {
            var query = new Uri(qrCodeUri).Query;
            var queryParameters = System.Web.HttpUtility.ParseQueryString(query);
            return queryParameters["secret"] ?? "Unknown";
        }

    }
}
