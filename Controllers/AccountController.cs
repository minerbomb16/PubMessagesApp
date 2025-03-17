using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using PubMessagesApp.Data;
using PubMessagesApp.Models;
using PubMessagesApp.ViewModels;
using System.Net;

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

            await CreateDelay(1000);

            var user = await _userManager.FindByEmailAsync(model.Email);
            var ipAddress = !string.IsNullOrEmpty(model.UserIp) && IPAddress.TryParse(model.UserIp, out _) ? model.UserIp : "Unknown";
            var timestamp = DateTime.Now;
            bool loginSuccess = false;
            string dbPath = Path.Combine(_env.ContentRootPath, "Data", "country.mmdb");
            string location = "Unknown";

            try
            {
                if (!System.IO.File.Exists(dbPath)) throw new FileNotFoundException("Brak dostępu do bazy.", dbPath);
                if (!IPAddress.TryParse(ipAddress, out IPAddress ip)) throw new FormatException("Zły IP.");
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
                var lockoutEnd = await _userManager.GetLockoutEndDateAsync(user);
                if (lockoutEnd.HasValue && lockoutEnd.Value > DateTimeOffset.UtcNow)
                {
                    var remainingLockout = lockoutEnd.Value - DateTimeOffset.UtcNow;
                    ViewData["Error"] = $"Konto jest zablokowane. Spróbuj ponownie za {remainingLockout.Minutes} min {remainingLockout.Seconds} s.";
                    return View(model);
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
                        HttpContext.Session.SetString("UserPassword", model.Password);
                        HttpContext.Session.SetString("UserId", user.Id);
                        if (!user.IsGoogleAuthenticatorConfigured) return RedirectToAction("GoogleAuthenticatorSetup", "Authenticator");
                        return RedirectToAction("VerifyGoogleAuthenticator", "Authenticator");
                    }
                    else
                    {
                        await _userManager.AccessFailedAsync(user);
                    }
                }
            }
            else
            {
                ViewData["Error"] = "Nieprawidłowe dane logowania.";
                return View(model);
            }

            var failedAttempts = await _userManager.GetAccessFailedCountAsync(user);
            var remainingAttempts = maxAttempts - failedAttempts - 1;
            if (remainingAttempts <= 0)
            {
                await _userManager.SetLockoutEndDateAsync(user, DateTimeOffset.UtcNow.AddMinutes(lockoutMinutes));
                await _userManager.ResetAccessFailedCountAsync(user);
                ViewData["Error"] = $"Konto zostało zablokowane na {lockoutMinutes} minut.";
            }
            else
            {
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
            if (existingUser != null && !await _userManager.IsEmailConfirmedAsync(existingUser))
            {
                var result = await _userManager.DeleteAsync(existingUser);
                if (!result.Succeeded) return View(model);
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
                var confirmationLink = Url.Action("ConfirmEmail", "Email", new { userId = user.Id, token = encodedToken }, "https");
                TempData["Email"] = model.Email;
                TempData["ConfirmationLink"] = confirmationLink;
                return RedirectToAction("RegistrationConfirmation", "Email");
            }

            foreach (var error in createResult.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }

            return View(model);
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
            ClearSensitiveSessionData(HttpContext.Session);
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
            if (string.IsNullOrEmpty(userIp)) return Json(new { success = false, error = "Adres IP jest wymagany." });

            HttpContext.Items["UserIp"] = userIp;
            return Json(new { success = true });
        }

        public static void ClearSensitiveSessionData(ISession session)
        {
            session.Remove("UserPassword");
            session.Remove("UserId");
            session.Remove("NewPassword");
        }

        public static Task CreateDelay(int milliseconds)
        {
            var tcs = new TaskCompletionSource<bool>();
            var timer = new System.Timers.Timer(milliseconds) { AutoReset = false };
            timer.Elapsed += (sender, args) =>
            {
                timer.Dispose();
                tcs.SetResult(true);
            };
            timer.Start();
            return tcs.Task;
        }
    }
}