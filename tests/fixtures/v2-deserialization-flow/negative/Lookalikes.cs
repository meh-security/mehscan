class Lookalikes
{
    object Parse(dynamic Request)
    {
        return CustomJsonSerializer.Deserialize<UploadDto>(Request.Form["payload"]);
    }
}
