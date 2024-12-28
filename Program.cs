using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using PubMessagesApp.Data;
using PubMessagesApp.Models;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllersWithViews();

builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlite(builder.Configuration.GetConnectionString("DefaultConnection")));

builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
{
    options.Password.RequireDigit = true;
    options.Password.RequireLowercase = true;
    options.Password.RequireNonAlphanumeric = true;
    options.Password.RequireUppercase = true;
    options.Password.RequiredLength = 8;
    options.Password.RequiredUniqueChars = 1;
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);
    options.Lockout.MaxFailedAccessAttempts = 5;
    options.Lockout.AllowedForNewUsers = true;
    options.User.RequireUniqueEmail = true;
})
.AddEntityFrameworkStores<ApplicationDbContext>()
.AddDefaultTokenProviders();

builder.Services.ConfigureApplicationCookie(options =>
{
    options.Cookie.HttpOnly = true; // Zapobiega dostêpowi do ciasteczek przez JavaScript
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always; // Wymaga HTTPS
    options.Cookie.SameSite = SameSiteMode.Strict; // Ogranicza wysy³anie ciasteczek tylko do tej samej domeny
    options.Cookie.Name = "AuthCookie"; // Dostosowana nazwa ciasteczka
    options.ExpireTimeSpan = TimeSpan.FromMinutes(60); // Czas ¿ycia ciasteczka
    options.SlidingExpiration = true; // Odœwie¿a czas ¿ycia ciasteczka po aktywnoœci
    options.LoginPath = "/Account/Login"; // Œcie¿ka do logowania
    options.LogoutPath = "/Account/Logout"; // Œcie¿ka do wylogowania
    options.AccessDeniedPath = "/Account/AccessDenied"; // Œcie¿ka do b³êdu dostêpu
});

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    // Wymuszanie HTTPS nawet w œrodowisku developerskim
    app.UseHttpsRedirection();
}
else
{
    // W œrodowisku produkcyjnym, dodaj HSTS dla dodatkowego bezpieczeñstwa
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();

// Dodanie polityki Content-Security-Policy (CSP)
app.Use(async (context, next) =>
{
    var nonce = Convert.ToBase64String(Guid.NewGuid().ToByteArray());
    context.Items["CSPNonce"] = nonce;

    context.Response.Headers.Add("Content-Security-Policy",
        "default-src 'self'; " +
        "script-src 'self' https://cdnjs.cloudflare.com https://code.jquery.com https://cdn.jsdelivr.net https://stackpath.bootstrapcdn.com 'nonce-" + nonce + "'; " +
        "style-src 'self' https://stackpath.bootstrapcdn.com 'nonce-" + nonce + "'; " +
        "img-src 'self' data:; " + // Zezwala na obrazy z `data:`
        "connect-src 'self' http://localhost:* https://localhost:* ws://localhost:* wss://localhost:*; " +
        "frame-src 'self';");

    await next();
});

// Mapowanie tras
app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Messages}/{action=Index}/{id?}");

// Automatyczne migrowanie bazy danych
using (var scope = app.Services.CreateScope())
{
    var services = scope.ServiceProvider;
    var context = services.GetRequiredService<ApplicationDbContext>();
    context.Database.Migrate();
}

// Uruchomienie aplikacji
app.Run();
