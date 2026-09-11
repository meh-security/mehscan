class WebSecurity
{
    void Configure()
    {
        app.MapGet("/admin", handler);
        app.UseAuthentication();
        endpoint.RequireAuthorization("admins");
    }
}
