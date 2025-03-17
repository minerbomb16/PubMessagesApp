using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using PubMessagesApp.Models;
using PubMessagesApp.ViewModels;

namespace PubMessagesApp.Controllers
{
    public class PassChangeController : Controller
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;

        public PassChangeController(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager)
        {
            _userManager = userManager;
            _signInManager = signInManager;
        }

        [Authorize]
        [HttpGet]
        public IActionResult ChangePassword()
        {
            return View();
        }

        [Authorize]
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ChangePassword(ChangePasswordViewModel model)
        {
            if (!ModelState.IsValid) return View(model);

            var delayTask = AccountController.CreateDelay(1000);
            await delayTask;

            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                AccountController.ClearSensitiveSessionData(HttpContext.Session);
                return RedirectToAction("Login");
            }
            var result = await _signInManager.CheckPasswordSignInAsync(user, model.CurrentPassword, false);
            if (!result.Succeeded)
            {
                ViewData["Error"] = "Nieprawidłowe obecne hasło.";
                return View(model);
            }

            HttpContext.Session.SetString("UserId", user.Id);
            HttpContext.Session.SetString("UserPassword", model.CurrentPassword);
            HttpContext.Session.SetString("NewPassword", model.NewPassword);

            return RedirectToAction("VerifyChangePassword", "Authenticator");
        }
    }
}
