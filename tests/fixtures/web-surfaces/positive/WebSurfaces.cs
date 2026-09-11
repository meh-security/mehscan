class WebSurfaces
{
    void Review(string html, string location)
    {
        response.WriteAsync(html);
        response.Redirect(location);
        var uploads = request.Form.Files;
    }
}
