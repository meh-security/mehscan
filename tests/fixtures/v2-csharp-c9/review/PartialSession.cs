using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

public static class PartialSession
{
    public static void Configure(IServiceCollection services)
    {
        services.Configure<SessionOptions>(options =>
        {
            options.Cookie.HttpOnly = true;
        });
    }
}
