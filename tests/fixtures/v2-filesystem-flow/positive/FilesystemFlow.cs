class FilesystemFlow
{
    string Direct(dynamic Request)
    {
        return File.ReadAllText(Request.Query["direct"]);
    }

    void Propagated(dynamic Request, byte[] content)
    {
        var requested = Request.Query["propagated"];
        var forwardedValue = requested;
        File.WriteAllBytes(forwardedValue, content);
    }

    string Canonicalized(dynamic Request)
    {
        var canonical = Path.GetFullPath(Request.Query["protected"]);
        return File.ReadAllText(canonical);
    }

    bool Contained(string candidate, string root)
    {
        return Path.GetFullPath(candidate).StartsWith(Path.GetFullPath(root), StringComparison.Ordinal);
    }
}
