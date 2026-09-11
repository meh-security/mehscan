class UploadFlow
{
    void Direct(dynamic Request, string content)
    {
        File.WriteAllText(Request.Form.Files[0].FileName, content);
    }

    void Propagated(dynamic Request, string content)
    {
        var requested = Request.Form.Files[0].FileName;
        var forwardedValue = requested;
        File.WriteAllText(forwardedValue, content);
    }

    void Canonicalized(dynamic Request, string content)
    {
        var destination = Path.GetFullPath(Request.Form.Files[0].FileName);
        File.WriteAllText(destination, content);
    }

    bool ValidBasename(string filename)
    {
        return Path.GetFileName(filename) == filename;
    }
}
