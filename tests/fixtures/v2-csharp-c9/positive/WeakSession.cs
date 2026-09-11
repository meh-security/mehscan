using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

public static class WeakSession
{
    public static void Configure(IServiceCollection services)
    {
        services.AddSession(options =>
        {
            options.Cookie.HttpOnly = false;
            options.Cookie.SecurePolicy = CookieSecurePolicy.None;
            options.Cookie.SameSite = SameSiteMode.None;
        });
    }
}
