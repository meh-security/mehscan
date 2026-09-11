using System;
using System.IO;

public class FilesystemSafe
{
    public string FixedRead()
    {
        return File.ReadAllText("settings.json");
    }

    public string UnrelatedConsoleRead()
    {
        return Console.ReadLine();
    }
}
