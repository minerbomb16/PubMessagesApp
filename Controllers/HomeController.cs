// Controllers/HomeController.cs
using Microsoft.AspNetCore.Mvc;

namespace PubMessagesApp.Controllers
{
    public class HomeController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }

        // Opcjonalnie, dodaj akcj� dla strony b��du
        public IActionResult Error()
        {
            return View();
        }
    }
}
