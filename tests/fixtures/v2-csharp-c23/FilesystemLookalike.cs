using System;

public static class File
{
    public static string ReadAllText(string path) => path;
}

public class FilesystemLookalike
{
    public string Read()
    {
        return File.ReadAllText(Console.ReadLine());
    }
}
