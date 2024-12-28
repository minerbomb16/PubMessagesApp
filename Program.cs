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
    options.Cookie.HttpOnly = true; // Zapobiega dost�powi do ciasteczek przez JavaScript
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always; // Wymaga HTTPS
    options.Cookie.SameSite = SameSiteMode.Strict; // Ogranicza wysy�anie ciasteczek tylko do tej samej domeny
    options.Cookie.Name = "AuthCookie"; // Dostosowana nazwa ciasteczka
    options.ExpireTimeSpan = TimeSpan.FromMinutes(60); // Czas �ycia ciasteczka
    options.SlidingExpiration = true; // Od�wie�a czas �ycia ciasteczka po aktywno�ci
    options.LoginPath = "/Account/Login"; // �cie�ka do logowania
    options.LogoutPath = "/Account/Logout"; // �cie�ka do wylogowania
    options.AccessDeniedPath = "/Account/AccessDenied"; // �cie�ka do b��du dost�pu
});

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    // Wymuszanie HTTPS nawet w �rodowisku developerskim
    app.UseHttpsRedirection();
}
else
{
    // W �rodowisku produkcyjnym, dodaj HSTS dla dodatkowego bezpiecze�stwa
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
