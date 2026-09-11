class RequestSources
{
    void Review(dynamic Request)
    {
        var query = Request.Query["q"];
        var body = Request.Form["email"];
        var route = Request.RouteValues["id"];
        var header = Request.Headers["X-Trace"];
        var cookie = Request.Cookies["session"];
    }
}
