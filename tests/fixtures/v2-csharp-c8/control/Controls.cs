using System.Data.Common;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;

public static class StrongIdentityPolicy
{
    public static void Configure(IServiceCollection services)
    {
        services.Configure<IdentityOptions>(options =>
        {
            options.Password.RequiredLength = 15;
            options.Password.RequiredUniqueChars = 1;
            options.Lockout.MaxFailedAccessAttempts = 5;
            options.Lockout.AllowedForNewUsers = true;
        });
    }
}

public static class ParameterizedQuery
{
    public static object Find(DbConnection connection, string value)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "select * from users where name = @name";
        command.Parameters.Add(CreateParameter("@name", value));
        return command.ExecuteReader();
    }

    private static object CreateParameter(string name, string value) => value;
}
