using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using PubMessagesApp.Models;
using PubMessagesApp.ViewModels;

namespace PubMessagesApp.Controllers
{
    public class AccountController : Controller
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;

        public AccountController(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager)
        {
            _userManager = userManager;
            _signInManager = signInManager;
        }

        public async Task<IActionResult> Login(LoginViewModel model)
        {
            if (!ModelState.IsValid) return View(model);

            const int maxAttempts = 5;
            const int lockoutMinutes = 5;

            // Opóźnienie 1 sekundy (anty-bruteforce)
            await Task.Delay(1000);

            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null)
            {
                // Nie informujemy, że użytkownik nie istnieje
                ViewData["Error"] = "Nieprawidłowe dane logowania.";
                return View(model);
            }

            // Sprawdzenie, czy konto jest zablokowane
            var lockoutEnd = await _userManager.GetLockoutEndDateAsync(user);
            if (lockoutEnd.HasValue && lockoutEnd.Value > DateTimeOffset.UtcNow)
            {
                var remainingLockout = lockoutEnd.Value - DateTimeOffset.UtcNow;
                ViewData["Error"] = $"Konto jest zablokowane. Spróbuj ponownie za {remainingLockout.Minutes} min {remainingLockout.Seconds} s.";
                return View(model); // Nie weryfikujemy hasła
            }

            // Próba logowania
            var result = await _signInManager.PasswordSignInAsync(user.UserName, model.Password, false, lockoutOnFailure: false);
            if (result.Succeeded)
            {
                // Zresetuj liczbę nieudanych prób po udanym logowaniu
                await _userManager.ResetAccessFailedCountAsync(user);
                return RedirectToAction("Index", "Messages");
            }

            // Zwiększ liczbę nieudanych prób
            await _userManager.AccessFailedAsync(user);

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

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterViewModel model)
        {
            if (!ModelState.IsValid) return View(model);

            var userExists = await _userManager.FindByEmailAsync(model.Email);
            if (userExists != null)
            {
                ViewData["Error"] = "Konto na podany adres email już istnieje.";
                return View(model);
            }

            var user = new ApplicationUser { UserName = model.Email, Email = model.Email };
            user.GenerateKeys();
            var result = await _userManager.CreateAsync(user, model.Password);

            if (result.Succeeded)
            {
                return RedirectToAction("Login", "Account");
            }

            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }

            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout()
        {
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
    }
}
