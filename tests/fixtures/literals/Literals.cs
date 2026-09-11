using System.Diagnostics;

enum ToolMode
{
    Safe
}

class LiteralContext
{
    void Review()
    {
        const string Prefix = "safe/";
        const string Command = Prefix + "tool";
        Process.Start(Command);
        Process.Start(ToolMode.Safe);
    }
}
