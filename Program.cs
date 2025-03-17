using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using PubMessagesApp.Data;
using PubMessagesApp.Models;

var builder = WebApplication.CreateBuilder(args);

builder.WebHost.ConfigureKestrel(options =>
{
    options.ListenAnyIP(5000);
});

builder.Services.AddDataProtection()
    .PersistKeysToFileSystem(new DirectoryInfo(@"/app/dataprotection-keys"))
    .SetApplicationName("PubMessagesApp");

builder.Services.AddControllersWithViews(options =>
{
    options.Filters.Add(new AutoValidateAntiforgeryTokenAttribute());
}).AddSessionStateTempDataProvider();
builder.Services.AddSession();

builder.Services.AddDbContext<ApplicationDbContext>(options =>
{
    var password = Environment.GetEnvironmentVariable("DATABASE_PASSWORD");
    var connectionString = $"Data Source=PubMessagesDb.sqlite;Password={password};";
    options.UseSqlite(connectionString);
});

builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
{
    options.SignIn.RequireConfirmedEmail = true;
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
    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.SameSite = SameSiteMode.Strict;
    options.Cookie.Name = "AuthCookie";
    options.Cookie.IsEssential = true;
    options.ExpireTimeSpan = TimeSpan.FromMinutes(60);
    options.SlidingExpiration = true;
    options.LoginPath = "/Account/Login";
    options.LogoutPath = "/Account/Logout";
    options.AccessDeniedPath = "/Account/AccessDenied";
});

var app = builder.Build();

app.UseForwardedHeaders(new ForwardedHeadersOptions
{
    ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto
});

if (app.Environment.IsDevelopment())
{
    app.UseHttpsRedirection();
}
else
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();
}

app.UseStaticFiles();

app.UseRouting();
app.UseSession();
app.UseAuthentication();
app.UseAuthorization();

app.Use(async (context, next) =>
{
    var nonce = Convert.ToBase64String(Guid.NewGuid().ToByteArray());
    context.Items["CSPNonce"] = nonce;

    context.Response.Headers.Add("Content-Security-Policy",
        "default-src 'self'; " +
        "script-src 'self' https://cdnjs.cloudflare.com https://code.jquery.com https://cdn.jsdelivr.net https://stackpath.bootstrapcdn.com 'nonce-" + nonce + "'; " +
        "style-src 'self' https://stackpath.bootstrapcdn.com 'nonce-" + nonce + "'; " +
        "img-src 'self' data:; " +
        "connect-src 'self' http://localhost:* https://localhost:* ws://localhost:* wss://localhost:* https://api.ipify.org; " +
        "frame-ancestors 'self'; " +
        "form-action 'self';");

    context.Response.OnStarting(() =>
    {
        context.Response.Headers.Remove("Server");
        return Task.CompletedTask;
    });

    await next();
});

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Messages}/{action=Index}/{id?}");

using (var scope = app.Services.CreateScope())
{
    var services = scope.ServiceProvider;
    var context = services.GetRequiredService<ApplicationDbContext>();

    try
    {
        Console.WriteLine("Próba utworzenia bazy danych...");
        context.Database.Migrate();
        Console.WriteLine("Migracja zakoñczona sukcesem.");
    }
    catch (Exception ex)
    {
        Console.WriteLine($"B³¹d podczas migracji: {ex.Message}");
    }

    using (var connection = context.Database.GetDbConnection())
    {
        connection.Open();
        using (var command = connection.CreateCommand())
        {
            var password = Environment.GetEnvironmentVariable("DATABASE_PASSWORD");
            command.CommandText = $"PRAGMA key = '{password}';";
            command.ExecuteNonQuery();
        }
    }
}

app.Run();