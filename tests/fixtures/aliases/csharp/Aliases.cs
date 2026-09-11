using Proc = System.Diagnostics.Process;
using System.Diagnostics;
using static System.Diagnostics.Process;

class Aliases
{
    void Run(string command)
    {
        System.Diagnostics.Process.Start(command);
        Proc.Start(command);
        Process.Start(command);
        Start(command);
    }

    void ShadowedAlias(dynamic Proc, string command)
    {
        Proc.Start(command);
    }
}
