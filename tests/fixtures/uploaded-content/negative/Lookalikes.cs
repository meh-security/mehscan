class Lookalikes
{
    void Review(dynamic request)
    {
        var stream = request.Form.Attachments[0].OpenReadStream();
    }
}
