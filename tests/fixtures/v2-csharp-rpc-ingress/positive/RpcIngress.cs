using Grpc.Core;
using Microsoft.AspNetCore.SignalR;

public class RunnerGrpcService : Runner.RunnerBase
{
    public override Task<Reply> Run(RunRequest request, ServerCallContext context)
    {
        Process.Start(request.Command);
        return Task.FromResult(new Reply());
    }

    public override Task<Reply> Jump(RedirectRequest request, ServerCallContext context)
    {
        Results.Redirect(request.Location);
        return Task.FromResult(new Reply());
    }

    public override Task<Reply> Execute(string command, ServerCallContext context)
    {
        Process.Start(command);
        return Task.FromResult(new Reply());
    }
}

public class OperationsHub : Hub
{
    public Task Run(string command)
    {
        Process.Start(command);
        return Task.CompletedTask;
    }

    public Task Fetch(string endpoint, [FromServices] HttpClient client)
    {
        return client.GetAsync(endpoint);
    }

    public Task Submit(RunRequest request)
    {
        Process.Start(request.Command);
        return Task.CompletedTask;
    }

    public Task Broadcast(string user, string message)
    {
        Process.Start(message);
        return Task.CompletedTask;
    }
}

public class NavigationHub : Hub<IClient>
{
    [HubMethodName("Navigate")]
    public Task Jump(string location)
    {
        Results.Redirect(location);
        return Task.CompletedTask;
    }
}
