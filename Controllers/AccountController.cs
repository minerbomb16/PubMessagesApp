﻿using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using PubMessagesApp.Data;
using PubMessagesApp.Models;
using PubMessagesApp.ViewModels;
using MaxMind.GeoIP2;
using Microsoft.AspNetCore.Hosting;
using System.Net;
using Newtonsoft.Json;

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
            Console.WriteLine("Przesłane dane formularza:");
            Console.WriteLine($"Email: {model.Email}");
            Console.WriteLine($"Password: {model.Password}");
            Console.WriteLine($"UserIp: {model.UserIp}");

            if (!ModelState.IsValid) return View(model);

            const int maxAttempts = 5;
            const int lockoutMinutes = 5;

            // Opóźnienie 1 sekundy (anty-bruteforce)
            await Task.Delay(1000);

            var user = await _userManager.FindByEmailAsync(model.Email);
            var ipAddress = !string.IsNullOrEmpty(model.UserIp) ? model.UserIp : "Unknown";

            Console.WriteLine($"Rzeczywisty adres IP klienta: {ipAddress}");

            var timestamp = DateTime.Now;
            bool loginSuccess = false;

            //ipAddress = "	172.18.0.1"; // Adres IP do testów
            //ipAddress = "1.1.1.1";

            string dbPath = Path.Combine(_env.ContentRootPath, "Data", "country.mmdb");
            string location = "Unknown";

            try
            {
                Console.WriteLine("==============================================================");
                Console.WriteLine("Rozpoczęto mapowanie adresu IP na lokalizację");
                Console.WriteLine($"Ścieżka do bazy danych: {dbPath}");
                Console.WriteLine($"Adres IP: {ipAddress}");

                if (!System.IO.File.Exists(dbPath))
                {
                    Console.WriteLine("Baza danych nie istnieje na podanej ścieżce.");
                    throw new FileNotFoundException("Plik country.mmdb nie został znaleziony.", dbPath);
                }

                if (!IPAddress.TryParse(ipAddress, out IPAddress ip))
                {
                    Console.WriteLine($"Nieprawidłowy format adresu IP: {ipAddress}");
                    throw new FormatException("Adres IP ma nieprawidłowy format.");
                }

                using (var reader = new MaxMind.Db.Reader(dbPath))
                {
                    Console.WriteLine("Baza danych została poprawnie załadowana.");

                    // Znajdź dane dla adresu IP
                    var result = reader.Find<dynamic>(ip);

                    if (result != null)
                    {
                        Console.WriteLine("Dane dla adresu IP zostały znalezione.");

                        // Wyciąganie danych z dynamicznej struktury
                        string countryCode = result["country"] ?? "Unknown";
                        string countryName = result["country_name"] ?? "Unknown";
                        string continentCode = result["continent"] ?? "Unknown";
                        string continentName = result["continent_name"] ?? "Unknown";

                        Console.WriteLine($"Kod kraju: {countryCode}");
                        Console.WriteLine($"Nazwa kraju: {countryName}");
                        Console.WriteLine($"Kod kontynentu: {continentCode}");
                        Console.WriteLine($"Nazwa kontynentu: {continentName}");

                        // Zbudowanie pełnej lokalizacji
                        location = $"{countryName}, {continentName}";
                    }
                    else
                    {
                        Console.WriteLine("Adres IP nie został znaleziony w bazie.");
                    }
                }
            }
            catch (Exception ex)
            {
                location = "Unknown";

                Console.WriteLine("==============================================================");
                Console.WriteLine("Wystąpił błąd podczas mapowania adresu IP na lokalizację:");
                Console.WriteLine($"Błąd: {ex.Message}");
                Console.WriteLine($"Szczegóły: {ex.StackTrace}");
                Console.WriteLine("==============================================================");
            }

            Console.WriteLine($"Zakończono mapowanie. Wynik lokalizacji: {location}");
            Console.WriteLine("==============================================================");

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
                    var result = await _signInManager.PasswordSignInAsync(user.UserName, model.Password, false, lockoutOnFailure: false);
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
                        return RedirectToAction("Index", "Messages");
                    }
                    else
                    {
                        // Zwiększ liczbę nieudanych prób
                        await _userManager.AccessFailedAsync(user);
                    }
                }
            } else
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

        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult SaveUserIp([FromBody] dynamic request)
        {
            string userIp = request.userIp?.ToString();

            if (string.IsNullOrEmpty(userIp))
            {
                return Json(new { success = false, error = "Adres IP jest wymagany." });
            }

            HttpContext.Items["UserIp"] = userIp; // Przechowywanie IP w kontekście żądania
            Console.WriteLine($"Przypisano adres IP: {userIp}");

            return Json(new { success = true });
        }
    }
}
