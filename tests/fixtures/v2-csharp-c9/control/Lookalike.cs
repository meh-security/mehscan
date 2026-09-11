public static class Lookalike
{
    public static void Configure(dynamic services)
    {
        services.AddSessionCache(options =>
        {
            options.Cookie.HttpOnly = false;
        });
    }
}
