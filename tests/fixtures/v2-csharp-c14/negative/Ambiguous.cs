using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;

public class AmbiguousController : ControllerBase
{
    private readonly IRunnerService _runner;
    private readonly OverloadedRepository _overloaded;

    [HttpGet]
    public object DuplicateDispatch([FromQuery] string command) => _runner.Run(command);

    [HttpGet]
    public object AmbiguousOverload([FromQuery] string command) => _overloaded.Run(command);

    [HttpGet]
    public object ExpressionArgument([FromQuery] string command) => _overloaded.Exact(Normalize(command));

    [HttpGet]
    public object NamedArgument([FromQuery] string command) => _overloaded.Exact(command: command);

    [NonAction]
    public object NotAnAction(string command) => _overloaded.Exact(command);

    private static string Normalize(string value) => value;
}

public interface IRunnerService { }

public class FirstRunnerService : IRunnerService
{
    public object Run(string command) => Process.Start(command);
}

public class SecondRunnerService : IRunnerService
{
    public object Run(string command) => Process.Start(command);
}

public class OverloadedRepository
{
    public object Run(string command) => Process.Start(command);
    public object Run(object command) => Process.Start(command.ToString());
    public object Exact(string command) => Process.Start(command);
}
