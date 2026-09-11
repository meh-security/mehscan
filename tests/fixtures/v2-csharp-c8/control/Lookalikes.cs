public sealed class FakeCommand
{
    public string CommandText { get; set; }
}

public sealed class FakeFactory
{
    public FakeCommand CreateCommand() => new FakeCommand();
}

public sealed class CustomIdentityOptions
{
    public PasswordPolicy Password { get; set; }
}

public sealed class PasswordPolicy
{
    public int RequiredLength { get; set; }
}

public static class Lookalikes
{
    public static object Query(string query, FakeFactory factory)
    {
        var command = factory.CreateCommand();
        command.CommandText = query;
        return command;
    }

    public static void Configure(dynamic services)
    {
        services.Configure<CustomIdentityOptions>(options =>
        {
            options.Password.RequiredLength = 1;
        });
    }
}

public static class UnexecutedFactoryCommand
{
    public static object Build(string query, System.Data.Common.DbConnection connection)
    {
        var command = connection.CreateCommand();
        command.CommandText = query;
        return command;
    }
}
