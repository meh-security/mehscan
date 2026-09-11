class HtmlFlow
{
    void Direct(dynamic Request, dynamic Response)
    {
        Response.WriteAsync(Request.Query["direct"]);
    }

    void Propagated(dynamic Request, dynamic Response)
    {
        var content = Request.Query["propagated"];
        var forwardedValue = content;
        Response.WriteAsync(forwardedValue);
    }

    void Encoded(dynamic Request, dynamic Response)
    {
        var encoded = HtmlEncoder.Default.Encode(Request.Query["encoded"]);
        Response.WriteAsync(encoded);
    }
}
