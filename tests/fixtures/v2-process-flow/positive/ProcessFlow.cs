class ProcessFlow
{
    void Direct(dynamic Request)
    {
        Process.Start(Request.Query["direct"]);
    }

    void Propagated(dynamic Request)
    {
        var command = Request.Query["propagated"];
        var forwardedValue = command;
        Process.Start(forwardedValue);
    }

    void Separated(dynamic Request, dynamic startInfo)
    {
        startInfo.ArgumentList.Add(Request.Query["argument"]);
    }
}
