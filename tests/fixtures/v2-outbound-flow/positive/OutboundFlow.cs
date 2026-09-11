using System.Net.Http;

class OutboundFlow
{
    object Direct(dynamic Request, HttpClient client)
    {
        return client.GetAsync(Request.Query["direct"]);
    }

    object Propagated(dynamic Request, HttpClient client)
    {
        var requested = Request.Query["propagated"];
        var forwardedValue = requested;
        return client.GetStringAsync(forwardedValue);
    }

    object Parsed(dynamic Request, HttpClient client)
    {
        var parsed = new Uri(Request.Query["parsed"]);
        return client.GetAsync(parsed);
    }

    bool ValidScheme(Uri parsed)
    {
        return parsed.Scheme == Uri.UriSchemeHttps;
    }
}
