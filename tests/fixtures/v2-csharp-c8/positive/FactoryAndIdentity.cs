using System.Data.Common;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;

public sealed class FactoryController : Controller
{
    [HttpGet]
    public object Query([FromQuery] string query, DbConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText = query;
        return command.ExecuteReader();
    }
}

public static class WeakIdentityPolicy
{
    public static void Configure(IServiceCollection services)
    {
        services.Configure<IdentityOptions>(options =>
        {
            options.Password.RequireDigit = false;
            options.Password.RequireLowercase = false;
            options.Password.RequireNonAlphanumeric = false;
            options.Password.RequireUppercase = false;
            options.Password.RequiredLength = 2;
            options.Password.RequiredUniqueChars = 0;
            options.Lockout.MaxFailedAccessAttempts = 50;
            options.Lockout.AllowedForNewUsers = false;
        });
    }
}
