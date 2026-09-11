class RedirectFlow
{
    void Direct(dynamic Request, dynamic Response)
    {
        Response.Redirect(Request.Query["direct"]);
    }

    void Propagated(dynamic Request, dynamic Response)
    {
        var requested = Request.Query["propagated"];
        var forwardedValue = requested;
        Response.Redirect(forwardedValue);
    }

    void Parsed(dynamic Request, dynamic Response)
    {
        var destination = new Uri(Request.Query["parsed"]);
        Response.Redirect(destination.ToString());
    }

    bool ValidLocal(string destination)
    {
        return Url.IsLocalUrl(destination);
    }
}
