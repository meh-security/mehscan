using Custom.Grpc.Core;
using Custom.SignalR;

public class LookalikeHub : Hub
{
    public Task Run(string command)
    {
        Process.Start(command);
        return Task.CompletedTask;
    }
}

public class LookalikeService : Fake.GeneratedBase
{
    public override Task<Reply> Run(RunRequest request, ServerCallContext context)
    {
        Process.Start(request.Command);
        return Task.FromResult(new Reply());
    }
}
