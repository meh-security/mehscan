using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

public static class StrongSession
{
    public static void Configure(IServiceCollection services)
    {
        services.AddSession(options =>
        {
            options.Cookie.HttpOnly = true;
            options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
            options.Cookie.SameSite = SameSiteMode.Lax;
        });
    }
}
