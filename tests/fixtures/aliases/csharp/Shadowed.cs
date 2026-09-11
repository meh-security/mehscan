using System.Diagnostics;

class Process
{
    public static void Start(string command) {}
}

class Shadowed
{
    void Run(string command)
    {
        Process.Start(command);
    }
}

