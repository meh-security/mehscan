class Lookalikes
{
    void Configure()
    {
        app.MapLocal("/admin", handler);
        app.UseIdentity();
        endpoint.RequirePolicy("admins");
    }
}
