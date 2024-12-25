// ViewModels/LoginViewModel.cs
using System.ComponentModel.DataAnnotations;

namespace PubMessagesApp.ViewModels
{
    public class LoginViewModel
    {
        [Required(ErrorMessage = "Adres email jest wymagany.")]
        [EmailAddress(ErrorMessage = "Nieprawidłowy format adresu email.")]
        [Display(Name = "Adres Email")]
        public string Email { get; set; }

        [Required(ErrorMessage = "Hasło jest wymagane.")]
        [DataType(DataType.Password)]
        [Display(Name = "Hasło")]
        public string Password { get; set; }

        [Display(Name = "Zapamiętaj mnie?")]
        public bool RememberMe { get; set; }
    }
}
