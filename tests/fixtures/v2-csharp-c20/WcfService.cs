using System.Diagnostics;

public class CommandService : ICommandService
{
    public string Execute(string command)
    {
        Process.Start(command);
        return "ok";
    }
}

public class SameNameLookalike
{
    public string Execute(string command)
    {
        Process.Start("fixed.exe");
        return command;
    }
}
