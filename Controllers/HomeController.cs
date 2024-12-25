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

        // Opcjonalnie, dodaj akcjê dla strony b³êdu
        public IActionResult Error()
        {
            return View();
        }
    }
}
