using System.Diagnostics;

class ProcessRunner
{
    void Run(string command)
    {
        Process.Start(command);
    }
}

