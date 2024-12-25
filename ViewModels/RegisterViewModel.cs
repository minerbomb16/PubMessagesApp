// ViewModels/RegisterViewModel.cs
using System.ComponentModel.DataAnnotations;

namespace PubMessagesApp.ViewModels
{
    public class RegisterViewModel
    {
        [Required(ErrorMessage = "Adres email jest wymagany.")]
        [EmailAddress(ErrorMessage = "Nieprawidłowy format adresu email.")]
        [Display(Name = "Adres Email")]
        public string Email { get; set; }

        [Required(ErrorMessage = "Hasło jest wymagane.")]
        [DataType(DataType.Password)]
        [Display(Name = "Hasło")]
        public string Password { get; set; }

        [Required(ErrorMessage = "Potwierdzenie hasła jest wymagane.")]
        [DataType(DataType.Password)]
        [Display(Name = "Potwierdź Hasło")]
        [Compare("Password", ErrorMessage = "Hasła muszą się zgadzać.")]
        public string ConfirmPassword { get; set; }
    }
}
