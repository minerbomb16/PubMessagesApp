// Data/ApplicationDbContext.cs
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using PubMessagesApp.Models;

namespace PubMessagesApp.Data
{
    public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options)
        {
        }

        // Możesz dodać dodatkowe DbSet tutaj, np.:
        // public DbSet<Message> Messages { get; set; }
    }
}
