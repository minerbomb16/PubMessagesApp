using System.ComponentModel.DataAnnotations;

namespace PubMessagesApp.ViewModels
{
    public class ChangePasswordViewModel
    {
        [Required(ErrorMessage = "Poprawne hasło jest wymagane.")]
        [DataType(DataType.Password)]
        public string CurrentPassword { get; set; }

        [Required(ErrorMessage = "Nowe hasło ejst wymagane.")]
        [DataType(DataType.Password)]
        public string NewPassword { get; set; }

        [Required(ErrorMessage = "Potwierdzenie hasła jest wymagane.")]
        [Compare("NewPassword", ErrorMessage = "Hasła muszą się zgadzać.")]
        [DataType(DataType.Password)]
        public string ConfirmPassword { get; set; }
    }
}
