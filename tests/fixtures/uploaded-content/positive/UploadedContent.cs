class UploadedContent
{
    void Review(dynamic request)
    {
        var stream = request.Form.Files[0].OpenReadStream();
    }
}
