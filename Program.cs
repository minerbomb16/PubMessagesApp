using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using PubMessagesApp.Data;
using PubMessagesApp.Models;
using System.Net;

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

builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;

    // Dodaj zakresy IP znane dla proxy
    options.KnownNetworks.Clear(); // Czy�ci domy�lne
    options.KnownProxies.Clear();  // Czy�ci domy�lne
    options.KnownNetworks.Add(new Microsoft.AspNetCore.HttpOverrides.IPNetwork(
        IPAddress.Parse("172.18.0.0"), 16)); // Zakres IP Dockera
});

var app = builder.Build();

// Dodaj middleware do obs�ugi nag��wk�w przesy�anych przez proxy
app.UseForwardedHeaders();


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
    Console.WriteLine("Nag��wki proxy:");
    Console.WriteLine($"X-Forwarded-For: {context.Request.Headers["X-Forwarded-For"]}");
    Console.WriteLine($"X-Real-IP: {context.Request.Headers["X-Real-IP"]}");

    var nonce = Convert.ToBase64String(Guid.NewGuid().ToByteArray());
    context.Items["CSPNonce"] = nonce;

    context.Response.Headers.Add("Content-Security-Policy",
        "default-src 'self'; " +
        "script-src 'self' https://cdnjs.cloudflare.com https://code.jquery.com https://cdn.jsdelivr.net https://stackpath.bootstrapcdn.com 'nonce-" + nonce + "'; " +
        "style-src 'self' https://stackpath.bootstrapcdn.com 'nonce-" + nonce + "'; " +
        "img-src 'self' data:; " + // Zezwala na obrazy z `data:`
        "connect-src 'self' http://localhost:* https://localhost:* ws://localhost:* wss://localhost:* https://api.ipify.org; " + // Zezwolenie na po��czenia z API ipify
        "frame-src 'self';");

    context.Response.OnStarting(() =>
    {
        context.Response.Headers.Remove("Server");
        return Task.CompletedTask;
    });

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
