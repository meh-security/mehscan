using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;

public static class ReviewIdentityPolicy
{
    public static void Configure(IServiceCollection services)
    {
        services.Configure<IdentityOptions>(options =>
        {
            options.Password.RequiredLength = 10;
            options.Lockout.MaxFailedAccessAttempts = 5;
        });
    }
}
