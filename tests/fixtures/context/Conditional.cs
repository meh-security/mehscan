using System.Diagnostics;

class ConditionalContext
{
    void Review(string command)
    {
#if false
        Process.Start(command);
#endif

#if true
        Process.Start(command);
#endif

#if DEBUG
        Process.Start(command);
#endif
    }
}
