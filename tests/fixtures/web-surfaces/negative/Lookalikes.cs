class Lookalikes
{
    void Review(string html, string location)
    {
        response.WriteJson(html);
        response.Navigate(location);
        var uploads = request.Form.Attachments;
    }
}
