using Grpc.Core;
using Microsoft.AspNetCore.SignalR;

public class SignalRControlsHub : Hub
{
    [NonHubMethod]
    public Task Internal(string command)
    {
        Process.Start(command);
        return Task.CompletedTask;
    }

    private Task Private(string command)
    {
        Process.Start(command);
        return Task.CompletedTask;
    }

    public static Task Static(string command)
    {
        Process.Start(command);
        return Task.CompletedTask;
    }

    public Task Injected([FromServices] RunnerService service)
    {
        Process.Start(service.Command);
        return Task.CompletedTask;
    }

    public Task Cancellation(CancellationToken cancellation)
    {
        Process.Start(cancellation.ToString());
        return Task.CompletedTask;
    }

    public override Task OnDisconnectedAsync(Exception exception)
    {
        Process.Start(exception.Message);
        return Task.CompletedTask;
    }
}

public class GrpcControls : FakeBase
{
    public Task<Reply> MissingOverride(RunRequest request, ServerCallContext context)
    {
        Process.Start(request.Command);
        return Task.FromResult(new Reply());
    }
}

public class StreamingService : Streams.StreamsBase
{
    public override Task Stream(
        IAsyncStreamReader<RunRequest> requests,
        IServerStreamWriter<Reply> replies,
        ServerCallContext context)
    {
        Process.Start(requests.ToString());
        return Task.CompletedTask;
    }
}
